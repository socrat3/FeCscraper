#!/usr/bin/env python3
"""
SISTEMA INTEGRATO FATTURE ELETTRONICHE AdE - VERSIONE 12.02
Download completo con duplicazione nomi (originale + ID_SDI)
Controllo completezza download e gestione coppie fattura-metadato
FIX: Organizzazione corretta EMESSE/RICEVUTE e estrazione anno documento
Sviluppato da Salvatore Crapanzano
Data: 14-08-2025
"""

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

import json
import os
import sys
import re
import time
import shutil
import subprocess
import hashlib
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path
import logging
import pytz
from tqdm import tqdm
import argparse
from collections import defaultdict
from typing import Dict, List, Optional, Tuple, Any

# CONFIGURAZIONE
SCRIPT_VERSION = "12.02"
SCRIPT_DATE = "15-08-2025"
CONFIG_FILE = "config_ade_system.json"
DEFAULT_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.119 Safari/537.36'

def unix_timestamp():
    """Genera timestamp unix in millisecondi"""
    return str(int(datetime.now(tz=pytz.utc).timestamp() * 1000))

def create_client_folder_name(nome_azienda, piva, cf):
    """Crea nome cartella nel formato nome_azienda_piva_cf"""
    nome_clean = re.sub(r'[<>:"/\\|?*]', '_', nome_azienda.upper().strip())[:100]
    piva_clean = re.sub(r'[^0-9A-Z]', '', str(piva).upper())
    cf_clean = re.sub(r'[^0-9A-Z]', '', str(cf).upper())
    return f"{nome_clean}_{piva_clean}_{cf_clean}"

def calculate_sha256(file_path):
    """Calcola SHA256 di un file"""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except:
        return ""

def divide_in_trimestri(data_iniziale, data_finale):
    """Divide periodo in trimestri"""
    def aggiusta_fine_trimestre(d):
        if d.month < 4:
            return datetime(d.year, 3, 31)
        elif d.month < 7:
            return datetime(d.year, 6, 30)
        elif d.month < 10:
            return datetime(d.year, 9, 30)
        else:
            return datetime(d.year, 12, 31)
    
    d1 = datetime.strptime(data_iniziale, "%d%m%Y")
    d2 = datetime.strptime(data_finale, "%d%m%Y")
    trimestri = []
    
    while d1 <= d2:
        fine_trimestre = aggiusta_fine_trimestre(d1)
        if fine_trimestre >= d2:
            trimestri.append((d1.strftime("%d%m%Y"), d2.strftime("%d%m%Y")))
            break
        else:
            trimestri.append((d1.strftime("%d%m%Y"), fine_trimestre.strftime("%d%m%Y")))
        d1 = fine_trimestre + timedelta(days=1)
    
    return trimestri

def extract_anno_from_xml(file_path: Path) -> int:
    """
    Estrae l'anno dalla data di emissione del documento XML
    Cerca specificamente DatiGeneraliDocumento/Data
    """
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        # Namespace comuni fattura elettronica
        namespaces = {
            'p': 'http://ivaservizi.agenziaentrate.gov.it/docs/xsd/fatture/v1.2',
            'ns2': 'http://ivaservizi.agenziaentrate.gov.it/docs/xsd/fatture/v1.2',
            'ns3': 'http://ivaservizi.agenziaentrate.gov.it/docs/xsd/fatture/v1.0',
            '': 'http://ivaservizi.agenziaentrate.gov.it/docs/xsd/fatture/v1.2'  # default namespace
        }
        
        # Rimuovi namespace dal tag per semplificare la ricerca
        def strip_namespace(tag):
            return tag.split('}')[-1] if '}' in tag else tag
        
        # Cerca DatiGeneraliDocumento/Data in tutti i modi possibili
        data_trovata = None
        
        # Metodo 1: Ricerca diretta con e senza namespace
        for elem in root.iter():
            tag_name = strip_namespace(elem.tag)
            if tag_name == 'DatiGeneraliDocumento':
                for child in elem:
                    child_tag = strip_namespace(child.tag)
                    if child_tag == 'Data' and child.text:
                        data_trovata = child.text
                        break
                if data_trovata:
                    break
        
        # Metodo 2: XPath con namespace
        if not data_trovata:
            for ns_prefix, ns_uri in namespaces.items():
                try:
                    # Prova con namespace
                    if ns_prefix:
                        elem = root.find(f'.//{{{ns_uri}}}FatturaElettronicaBody/{{{ns_uri}}}DatiGenerali/{{{ns_uri}}}DatiGeneraliDocumento/{{{ns_uri}}}Data')
                    else:
                        elem = root.find('.//FatturaElettronicaBody/DatiGenerali/DatiGeneraliDocumento/Data')
                    
                    if elem is not None and elem.text:
                        data_trovata = elem.text
                        break
                except:
                    continue
        
        # Metodo 3: Ricerca semplificata senza considerare namespace
        if not data_trovata:
            # Cerca qualsiasi elemento Data dentro DatiGeneraliDocumento
            for elem in root.iter():
                if 'DatiGeneraliDocumento' in elem.tag:
                    for child in elem:
                        if 'Data' in child.tag and child.text:
                            # Verifica che sia una data valida (formato YYYY-MM-DD)
                            if re.match(r'^\d{4}-\d{2}-\d{2}', child.text):
                                data_trovata = child.text
                                break
                    if data_trovata:
                        break
        
        # Estrai anno dalla data trovata
        if data_trovata and len(data_trovata) >= 4:
            try:
                anno = int(data_trovata[:4])
                # Verifica che l'anno sia ragionevole (tra 2000 e 2030)
                if 2000 <= anno <= 2030:
                    return anno
            except ValueError:
                pass
        
    except Exception as e:
        pass
    
    # Fallback all'anno corrente
    return datetime.now().year

class FileRegistry:
    """Gestione registro file con doppia nomenclatura"""
    
    def __init__(self, registry_path: Path):
        self.registry_path = registry_path
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)
        self.data = self._load()
        
    def _load(self) -> Dict:
        """Carica registro esistente"""
        if self.registry_path.exists():
            try:
                with open(self.registry_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                pass
        return {
            "version": "2.0",
            "created": datetime.now().isoformat(),
            "files": {},
            "mapping_nomi": {},
            "stats": {
                "totale_fatture": 0,
                "totale_metadati": 0,
                "coppie_complete": 0
            }
        }
    
    def save(self):
        """Salva registro su disco"""
        self.data["last_update"] = datetime.now().isoformat()
        with open(self.registry_path, 'w', encoding='utf-8') as f:
            json.dump(self.data, f, ensure_ascii=False, indent=2)
    
    def add_file(self, id_sdi: str, nome_originale: str, tipo: str, paths: Dict):
        """Aggiunge file al registro"""
        if id_sdi not in self.data["files"]:
            self.data["files"][id_sdi] = {
                "id_sdi": id_sdi,
                "nome_originale": None,
                "nome_metadato_originale": None,
                "paths": {},
                "sha256": {},
                "coppia_completa": False,
                "data_download": datetime.now().isoformat()
            }
        
        if tipo == "fattura":
            self.data["files"][id_sdi]["nome_originale"] = nome_originale
            self.data["files"][id_sdi]["paths"].update(paths)
            self.data["mapping_nomi"][nome_originale] = id_sdi
            self.data["stats"]["totale_fatture"] += 1
        elif tipo == "metadato":
            self.data["files"][id_sdi]["nome_metadato_originale"] = nome_originale
            self.data["files"][id_sdi]["paths"].update(paths)
            self.data["stats"]["totale_metadati"] += 1
        
        # Verifica coppia completa
        file_info = self.data["files"][id_sdi]
        if file_info["nome_originale"] and file_info["nome_metadato_originale"]:
            file_info["coppia_completa"] = True
            self.data["stats"]["coppie_complete"] += 1
    
    def check_coppia_completa(self, id_sdi: str, base_dir: Path) -> Tuple[bool, List[str]]:
        """
        Verifica se la coppia fattura-metadato è completa
        Returns: (is_complete, missing_files)
        """
        if id_sdi not in self.data["files"]:
            return False, ["fattura", "metadato"]
        
        file_info = self.data["files"][id_sdi]
        missing = []
        
        # Verifica esistenza fisica dei file
        if "originale_fattura" in file_info.get("paths", {}):
            path = base_dir / file_info["paths"]["originale_fattura"]
            if not path.exists():
                missing.append("fattura_originale")
        else:
            missing.append("fattura")
            
        if "originale_metadato" in file_info.get("paths", {}):
            path = base_dir / file_info["paths"]["originale_metadato"]
            if not path.exists():
                missing.append("metadato_originale")
        else:
            missing.append("metadato")
        
        return len(missing) == 0, missing

    def file_exists_in_registry(self, id_sdi: str) -> bool:
        """Verifica se file esiste nel registro ed è presente fisicamente"""
        if id_sdi not in self.data["files"]:
            return False
        
        file_info = self.data["files"][id_sdi]
        # Se c'è un path per la fattura, verifica che esista fisicamente
        if "originale_fattura" in file_info.get("paths", {}):
            return True
        if "id_sdi_fattura" in file_info.get("paths", {}):
            return True
        
        return False

class DownloadStats:
    """Statistiche download per controllo completezza"""
    
    def __init__(self):
        self.stats = defaultdict(lambda: {
            "trovate": 0,
            "scaricate": 0,
            "errori": 0,
            "gia_presenti": 0,
            "dettagli": []
        })
        self.totale_previsto = 0
        self.totale_scaricato = 0
        
    def add_trovate(self, tipo: str, count: int):
        """Aggiunge fatture trovate nel JSON"""
        self.stats[tipo]["trovate"] += count
        self.totale_previsto += count
        
    def add_scaricata(self, tipo: str, id_fattura: str = None):
        """Registra download riuscito"""
        self.stats[tipo]["scaricate"] += 1
        self.totale_scaricato += 1
        if id_fattura:
            self.stats[tipo]["dettagli"].append({"id": id_fattura, "status": "OK"})
    
    def add_gia_presente(self, tipo: str, id_fattura: str = None):
        """Registra file già presente"""
        self.stats[tipo]["gia_presenti"] += 1
        self.totale_scaricato += 1
        if id_fattura:
            self.stats[tipo]["dettagli"].append({"id": id_fattura, "status": "PRESENTE"})
    
    def add_errore(self, tipo: str, id_fattura: str = None, errore: str = None):
        """Registra errore download"""
        self.stats[tipo]["errori"] += 1
        if id_fattura:
            self.stats[tipo]["dettagli"].append({"id": id_fattura, "status": "ERRORE", "msg": errore})
    
    def print_summary(self):
        """Stampa riepilogo statistiche"""
        print("\n" + "="*80)
        print("📊 RIEPILOGO DOWNLOAD")
        print("="*80)
        
        for tipo, dati in self.stats.items():
            print(f"\n📁 {tipo.upper()}:")
            print(f"   Trovate nel periodo: {dati['trovate']}")
            print(f"   Già presenti: {dati['gia_presenti']}")
            print(f"   Scaricate ora: {dati['scaricate']}")
            print(f"   Errori: {dati['errori']}")
            
            completezza = ((dati['gia_presenti'] + dati['scaricate']) / dati['trovate'] * 100) if dati['trovate'] > 0 else 0
            print(f"   Completezza: {completezza:.1f}%")
        
        print("\n" + "-"*80)
        print(f"📈 TOTALE COMPLESSIVO:")
        print(f"   Fatture previste: {self.totale_previsto}")
        print(f"   Fatture scaricate/presenti: {self.totale_scaricato}")
        completezza_totale = (self.totale_scaricato / self.totale_previsto * 100) if self.totale_previsto > 0 else 0
        print(f"   ✅ Completezza totale: {completezza_totale:.1f}%")
        
        if completezza_totale < 100:
            mancanti = self.totale_previsto - self.totale_scaricato
            print(f"   ⚠️ Fatture mancanti: {mancanti}")
        else:
            print(f"   ✅ Tutte le fatture sono state scaricate!")
        
        print("="*80)

class SistemaFattureV12:
    def __init__(self, config_file=CONFIG_FILE):
        self.config = self.load_config(config_file)
        self.session = None
        self.p_auth = ""
        self.headers_token = {}
        self.download_stats = DownloadStats()
        self.registry = None
        self.setup_logging()
        self.print_banner()
        
    def print_banner(self):
        """Stampa banner iniziale"""
        print(f"\n╔{'═'*78}╗")
        print(f"║{'SISTEMA FATTURE ADE v12.03':^78}║")
        print(f"║{'Organizzazione corretta EMESSE/RICEVUTE + Anno documento':^78}║")
        print(f"║{'14-08-2025 - Salvatore Crapanzano':^78}║")
        print(f"╚{'═'*78}╝\n")
    
    def load_config(self, config_file):
        """Carica configurazione"""
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            # Aggiungi configurazioni default se mancanti
            if 'configurazione_download' not in config:
                config['configurazione_download'] = {}
            
            # Gestione nuova struttura config per compatibilità
            config_download = config['configurazione_download']
            
            # Configurazioni di base
            config_download.setdefault('struttura_file', 'ENTRAMBE')
            config_download.setdefault('verifica_integrita_coppia', True)
            config_download.setdefault('preserva_nomi_originali', True)
            config_download.setdefault('decodifica_p7m_duplicata', True)
            config_download.setdefault('download_metadati', True)
            
            # Nuove configurazioni per gestione file esistenti
            if 'gestione_file' not in config_download:
                config_download['gestione_file'] = {}
            
            gestione_file = config_download['gestione_file']
            gestione_file.setdefault('salta_file_esistenti', True)
            gestione_file.setdefault('forza_riscaricamento', False)
            gestione_file.setdefault('forza_riscaricamento_corrotti', True)
            gestione_file.setdefault('verifica_integrita_coppia', True)
            
            # Retrocompatibilità con vecchia configurazione
            if 'salta_file_esistenti' in config_download:
                gestione_file['salta_file_esistenti'] = config_download['salta_file_esistenti']
            
            if 'directory_sistema' not in config:
                config['directory_sistema'] = {}
            
            config['directory_sistema'].setdefault('struttura_originali', 'originali')
            config['directory_sistema'].setdefault('struttura_id_sdi', 'id_sdi')
            
            return config
            
        except FileNotFoundError:
            print(f"❌ File config non trovato: {config_file}")
            self.create_default_config(config_file)
            sys.exit(1)
        except Exception as e:
            print(f"❌ Errore caricamento config: {e}")
            sys.exit(1)
    
    def create_default_config(self, config_file):
        """Crea configurazione di default"""
        default_config = {
            "credenziali_ade": {
                "codice_fiscale": "",
                "pin": "",
                "password": ""
            },
            "portfolio_clienti": {
                "cliente_001": {
                    "nome_azienda": "AZIENDA_ESEMPIO",
                    "partita_iva_diretta": "12345678901",
                    "codice_fiscale": "RSSMRA80A01H501Z",
                    "attivo": True
                }
            },
            "configurazione_download": {
                "struttura_file": "ENTRAMBE",
                "verifica_integrita_coppia": True,
                "preserva_nomi_originali": True,
                "decodifica_p7m_duplicata": True,
                "download_metadati": True,
                "gestione_file": {
                    "salta_file_esistenti": True,
                    "forza_riscaricamento": False,
                    "forza_riscaricamento_corrotti": True,
                    "verifica_integrita_coppia": True
                },
                "tentativi_massimi_download": 10
            },
            "directory_sistema": {
                "input_temp": "temp_download_ade",
                "output_base": "aziende_processate",
                "liste_fatture": "liste_fatture_json",
                "struttura_originali": "originali",
                "struttura_id_sdi": "id_sdi",
                "registri": "registri_file",
                "logs": "logs_sistema",
                "reports": "reports_sistema"
            },
            "logging": {
                "livello": "INFO",
                "file_log": True,
                "console_log": True
            }
        }
        
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(default_config, f, ensure_ascii=False, indent=2)
        print(f"✅ Config di esempio creata: {config_file}")
    
    def setup_logging(self):
        """Configura logging con supporto UTF-8"""
        log_dir = Path(self.config.get('directory_sistema', {}).get('logs', 'logs_sistema'))
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # Configurazione formatter
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        
        # Handler per file con encoding UTF-8
        file_handler = logging.FileHandler(log_dir / 'fatture_ade_v12.log', encoding='utf-8')
        file_handler.setFormatter(formatter)
        
        # Handler per console con gestione errori
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        
        # Configurazione logger
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.INFO)
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        self.logger = logger
    
    def login(self):
        """Login al portale AdE"""
        try:
            self.session = requests.Session()
            self.session.headers.update({
                'User-Agent': DEFAULT_USER_AGENT,
                'Connection': 'keep-alive'
            })
            
            # Cookies iniziali
            self.session.cookies.set('LFR_SESSION_STATE_20159', 'expired', 
                                    domain='ivaservizi.agenziaentrate.gov.it')
            self.session.cookies.set('LFR_SESSION_STATE_10811916', unix_timestamp(),
                                    domain='ivaservizi.agenziaentrate.gov.it')
            
            # Homepage
            r = self.session.get('https://ivaservizi.agenziaentrate.gov.it/portale/web/guest',
                               verify=False, timeout=30)
            if r.status_code != 200:
                raise Exception(f"Homepage non raggiungibile: {r.status_code}")
            
            # Login
            creds = self.config['credenziali_ade']
            payload = {
                '_58_saveLastPath': 'false',
                '_58_redirect': '',
                '_58_doActionAfterLogin': 'false',
                '_58_login': creds['codice_fiscale'],
                '_58_pin': creds['pin'],
                '_58_password': creds['password']
            }
            
            r = self.session.post(
                'https://ivaservizi.agenziaentrate.gov.it/portale/home?p_p_id=58&p_p_lifecycle=1&p_p_state=normal&p_p_mode=view&p_p_col_id=column-1&p_p_col_pos=3&p_p_col_count=4&_58_struts_action=%2Flogin%2Flogin',
                data=payload, verify=False, timeout=30
            )
            
            # Estrai token
            match = re.search(r"Liferay\.authToken\s*=\s*'([^']+)';", r.text)
            if not match:
                raise Exception("Token non trovato")
            
            self.p_auth = match.group(1)
            
            # Verifica login
            r = self.session.get(f'https://ivaservizi.agenziaentrate.gov.it/dp/api?v={unix_timestamp()}', timeout=30)
            if r.status_code != 200:
                raise Exception(f"Verifica login fallita: {r.status_code}")
            
            print("✅ Login completato")
            return True
            
        except Exception as e:
            print(f"❌ Errore login: {e}")
            return False
    
    def select_client(self, client_data):
        """Seleziona cliente"""
        try:
            cf = client_data.get('codice_fiscale', '')
            piva = client_data.get('partita_iva_diretta', '')
            
            base_url = 'https://ivaservizi.agenziaentrate.gov.it/portale/scelta-utenza-lavoro'
            
            # Prima richiesta con CF
            payload = {'cf_inserito': cf}
            r = self.session.post(
                f'{base_url}?p_auth={self.p_auth}&p_p_id=SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet&p_p_lifecycle=1&p_p_state=normal&p_p_mode=view&p_p_col_id=column-1&p_p_col_count=1&_SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet_javax.portlet.action=delegaDirettaAction',
                data=payload, timeout=30
            )
            
            # Seconda richiesta con P.IVA
            payload['sceltapiva'] = piva
            r = self.session.post(
                f'{base_url}?p_auth={self.p_auth}&p_p_id=SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet&p_p_lifecycle=1&p_p_state=normal&p_p_mode=view&p_p_col_id=column-1&p_p_col_count=1&_SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet_javax.portlet.action=delegaDirettaAction',
                data=payload, timeout=30
            )
            
            print(f"✅ Cliente selezionato: {client_data.get('nome_azienda', 'N/D')}")
            return True
            
        except Exception as e:
            print(f"❌ Errore selezione cliente: {e}")
            return False
    
    def setup_headers(self):
        """Setup headers per download CON ACCETTAZIONE DISCLAIMER"""
        try:
            # 1. Adesione al servizio
            print("📡 Adesione al servizio...")
            r = self.session.get(
                'https://ivaservizi.agenziaentrate.gov.it/ser/api/fatture/v1/ul/me/adesione/stato/',
                timeout=30
            )
            
            # 2. Ottieni Token B2B
            print("🔑 Richiesta token B2B...")
            headers_token = {
                'x-xss-protection': '1; mode=block',
                'strict-transport-security': 'max-age=16070400; includeSubDomains',
                'x-content-type-options': 'nosniff',
                'x-frame-options': 'deny'
            }
            
            r = self.session.get(
                f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/sc/tokenB2BCookie/get?v={unix_timestamp()}',
                headers=headers_token,
                timeout=30
            )
            
            if r.status_code != 200:
                raise Exception(f"Token B2B non ottenuto: HTTP {r.status_code}")
            
            xb2bcookie = r.headers.get('x-b2bcookie')
            xtoken = r.headers.get('x-token')
            
            if not xb2bcookie or not xtoken:
                raise Exception("Token B2B mancanti negli headers")
            
            print(f"✅ Token B2B ottenuti")
            
            # 3. Imposta headers completi
            self.session.headers.update({
                'Host': 'ivaservizi.agenziaentrate.gov.it',
                'Referer': f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-web/?v={unix_timestamp()}',
                'Accept': 'application/json, text/plain, */*',
                'Accept-Encoding': 'gzip, deflate, br',
                'Accept-Language': 'it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7,fr;q=0.6',
                'DNT': '1',
                'X-XSS-Protection': '1; mode=block',
                'Strict-Transport-Security': 'max-age=16070400; includeSubDomains',
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': 'deny',
                'x-b2bcookie': xb2bcookie,
                'x-token': xtoken,
                'User-Agent': DEFAULT_USER_AGENT
            })
            
            self.headers_token = {
                'x-b2bcookie': xb2bcookie,
                'x-token': xtoken
            }
            
            # 4. Accetta disclaimer
            print("📜 Accettazione condizioni servizio...")
            r = self.session.get(
                f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/disclaimer/accetta?v={unix_timestamp()}',
                headers=self.headers_token,
                timeout=30
            )
            
            if r.status_code == 200:
                print("✅ Condizioni accettate")
            else:
                print(f"⚠️ Accettazione condizioni: HTTP {r.status_code}")
            
            print("✅ Headers configurati completamente")
            return True
            
        except Exception as e:
            print(f"❌ Errore setup headers: {e}")
            return False
    
    def extract_original_filename(self, content_disposition: str) -> Optional[str]:
        """Estrae nome file originale ESATTO dal Content-Disposition"""
        if not content_disposition:
            return None
        
        # Pattern per filename*=UTF-8''
        match = re.search(r"filename\*\s*=\s*(?:UTF-8''|utf-8'')?([^;]+)", content_disposition)
        if match:
            filename = match.group(1).strip(' "\'')
            # Decodifica URL encoding se presente
            from urllib.parse import unquote
            return unquote(filename)
        
        # Pattern standard filename=
        match = re.search(r'filename\s*=\s*"?([^";]+)"?', content_disposition)
        if match:
            return match.group(1).strip(' "\'')
        
        return None
    
    def download_lista_fatture(self, tipo, data_inizio, data_fine, client_folder, ricerca_per="ricezione"):
        """Scarica e salva JSON lista fatture"""
        try:
            # URL per tipo documento
            urls = {
                'emesse': f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fe/emesse/dal/{data_inizio}/al/{data_fine}',
                'ricevute_ricezione': f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fe/ricevute/dal/{data_inizio}/al/{data_fine}/ricerca/ricezione',
                'ricevute_emissione': f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fe/ricevute/dal/{data_inizio}/al/{data_fine}/ricerca/emissione',
                'transfrontaliere_emesse': f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/ft/emesse/dal/{data_inizio}/al/{data_fine}',
                'transfrontaliere_ricevute': f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/ft/ricevute/dal/{data_inizio}/al/{data_fine}',
                'messe_disposizione': f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fe/mc/dal/{data_inizio}/al/{data_fine}'
            }
            
            # Gestione ricevute con doppia modalità
            if tipo == 'ricevute':
                tipo_key = f'ricevute_{ricerca_per}'
            else:
                tipo_key = tipo
            
            if tipo_key not in urls:
                return None
            
            url = urls[tipo_key] + f'?v={unix_timestamp()}'
            
            # Headers
            headers = {
                'Host': 'ivaservizi.agenziaentrate.gov.it',
                'referer': f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-web/?v={unix_timestamp()}',
                'accept': 'application/json, text/plain, */*',
                'accept-encoding': 'gzip, deflate, br',
                'accept-language': 'it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7,fr;q=0.6',
                'DNT': '1',
                'x-xss-protection': '1; mode=block',
                'strict-transport-security': 'max-age=16070400; includeSubDomains',
                'x-content-type-options': 'nosniff',
                'x-frame-options': 'deny',
                'x-b2bcookie': self.headers_token.get('x-b2bcookie'),
                'x-token': self.headers_token.get('x-token'),
                'User-Agent': DEFAULT_USER_AGENT
            }
            
            # Download
            r = self.session.get(url, headers=headers, timeout=60, verify=False)
            
            # Crea directory per liste JSON
            liste_dir = Path(self.config['directory_sistema'].get('liste_fatture', 'liste_fatture_json'))
            liste_dir.mkdir(parents=True, exist_ok=True)
            
            # Nome file con formato richiesto
            if tipo == 'ricevute':
                filename = f"{client_folder}_{tipo}_{ricerca_per}_{data_inizio}_{data_fine}.json"
            else:
                filename = f"{client_folder}_{tipo}_{data_inizio}_{data_fine}.json"
            
            json_path = liste_dir / filename
            
            if r.status_code == 200:
                try:
                    data = r.json()
                    fatture = data.get('fatture', [])
                    
                    # Salva JSON
                    with open(json_path, 'w', encoding='utf-8') as f:
                        json.dump(data, f, ensure_ascii=False, indent=2)
                    
                    # Aggiorna statistiche
                    self.download_stats.add_trovate(tipo_key, len(fatture))
                    
                    if fatture:
                        print(f"✅ Lista {tipo_key}: {len(fatture)} fatture trovate -> {filename}")
                    else:
                        print(f"🔭 Lista {tipo_key}: nessuna fattura nel periodo -> {filename} (vuoto)")
                    
                    return json_path
                    
                except json.JSONDecodeError as e:
                    print(f"❌ Errore parsing JSON per {tipo_key}: {e}")
                    return None
            else:
                print(f"⚠️ Lista {tipo_key} non disponibile (HTTP {r.status_code})")
                return None
                
        except Exception as e:
            print(f"❌ Errore download lista {tipo}: {e}")
            return None
    
    def check_file_exists(self, id_fattura: str, temp_dir: Path) -> bool:
        """
        Verifica se il file esiste già basandosi sulla configurazione
        """
        try:
            # Controlla configurazione skip file esistenti
            gestione_file = self.config.get('configurazione_download', {}).get('gestione_file', {})
            salta_file_esistenti = gestione_file.get('salta_file_esistenti', True)
            
            if not salta_file_esistenti:
                return False  # Non saltare mai se configurato per scaricare sempre
            
            # Controlla nel registry prima
            if self.registry and self.registry.file_exists_in_registry(id_fattura):
                # Verifica fisica del file
                if gestione_file.get('verifica_integrita_coppia', True):
                    is_complete, missing = self.registry.check_coppia_completa(id_fattura, temp_dir)
                    return is_complete
                else:
                    return True
            
            # Fallback: controlla esistenza fisica diretta
            struttura_file = self.config['configurazione_download'].get('struttura_file', 'ENTRAMBE')
            
            if struttura_file in ['ENTRAMBE', 'ORIGINALE']:
                dir_originali = temp_dir / self.config['directory_sistema'].get('struttura_originali', 'originali')
                # Cerca file con pattern ID_SDI
                for file_path in dir_originali.glob(f"*{id_fattura}*"):
                    if file_path.is_file() and file_path.stat().st_size > 0:
                        return True
            
            if struttura_file in ['ENTRAMBE', 'ID_SDI']:
                dir_id_sdi = temp_dir / self.config['directory_sistema'].get('struttura_id_sdi', 'id_sdi')
                # Cerca file con pattern ID_SDI
                fattura_file = dir_id_sdi / f"{id_fattura}_FATTURA.xml"
                fattura_file_p7m = dir_id_sdi / f"{id_fattura}_FATTURA.p7m"
                
                if (fattura_file.exists() and fattura_file.stat().st_size > 0) or \
                   (fattura_file_p7m.exists() and fattura_file_p7m.stat().st_size > 0):
                    return True
            
            return False
            
        except Exception as e:
            self.logger.warning(f"Errore controllo esistenza file {id_fattura}: {e}")
            return False
    
    def download_fattura_completa(self, id_fattura: str, temp_dir: Path, tipo_doc: str) -> bool:
        """
        Scarica fattura + metadato mantenendo ENTRAMBI i nomi (originale e ID_SDI)
        VERSIONE CORRETTA per gestire sempre ENTRAMBE le strutture
        """
        try:
            struttura_file = self.config['configurazione_download'].get('struttura_file', 'ENTRAMBE')
            gestione_file = self.config.get('configurazione_download', {}).get('gestione_file', {})
            
            # Per modalità ENTRAMBE, NON saltare subito anche se esiste in una struttura
            # Dobbiamo verificare che esista in ENTRAMBE
            if struttura_file == 'ENTRAMBE':
                # Verifica esistenza in entrambe le strutture
                exists_originali = False
                exists_id_sdi = False
                
                dir_originali = temp_dir / self.config['directory_sistema'].get('struttura_originali', 'originali')
                dir_id_sdi = temp_dir / self.config['directory_sistema'].get('struttura_id_sdi', 'id_sdi')
                
                # Verifica cartella originali
                if dir_originali.exists():
                    for file_path in dir_originali.glob(f"*{id_fattura}*"):
                        if file_path.is_file() and file_path.stat().st_size > 0 and 'METADATO' not in file_path.name:
                            exists_originali = True
                            break
                
                # Verifica cartella id_sdi
                if dir_id_sdi.exists():
                    fattura_file = dir_id_sdi / f"{id_fattura}_FATTURA.xml"
                    fattura_file_p7m = dir_id_sdi / f"{id_fattura}_FATTURA.p7m"
                    if (fattura_file.exists() and fattura_file.stat().st_size > 0) or \
                       (fattura_file_p7m.exists() and fattura_file_p7m.stat().st_size > 0):
                        exists_id_sdi = True
                
                # Se esiste in entrambe e configurato per saltare, allora salta
                if exists_originali and exists_id_sdi and gestione_file.get('salta_file_esistenti', True):
                    self.download_stats.add_gia_presente(tipo_doc, id_fattura)
                    self.logger.info(f"File già presente in entrambe le strutture: {id_fattura}")
                    return True
                
                # Log dettagliato per debug
                if not exists_originali:
                    self.logger.info(f"File mancante in originali per {id_fattura}, procedo con download")
                if not exists_id_sdi:
                    self.logger.info(f"File mancante in id_sdi per {id_fattura}, procedo con download")
                    
            else:
                # Per modalità singola (ORIGINALE o ID_SDI), usa il check normale
                if self.check_file_exists(id_fattura, temp_dir):
                    self.download_stats.add_gia_presente(tipo_doc, id_fattura)
                    self.logger.info(f"File già presente saltato: {id_fattura}")
                    return True
            
            # Crea SEMPRE entrambe le sottocartelle per modalità ENTRAMBE
            dirs_to_create = []
            if struttura_file in ['ENTRAMBE', 'ORIGINALE']:
                dir_originali = temp_dir / self.config['directory_sistema'].get('struttura_originali', 'originali')
                dir_originali.mkdir(parents=True, exist_ok=True)
                dirs_to_create.append(('originali', dir_originali))
                self.logger.debug(f"Creata/verificata directory originali: {dir_originali}")
            
            if struttura_file in ['ENTRAMBE', 'ID_SDI']:
                dir_id_sdi = temp_dir / self.config['directory_sistema'].get('struttura_id_sdi', 'id_sdi')
                dir_id_sdi.mkdir(parents=True, exist_ok=True)
                dirs_to_create.append(('id_sdi', dir_id_sdi))
                self.logger.debug(f"Creata/verificata directory id_sdi: {dir_id_sdi}")
            
            # Download fattura
            url_fattura = f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fatture/file/{id_fattura}?tipoFile=FILE_FATTURA&download=1&v={unix_timestamp()}'
            
            headers = {
                'Host': 'ivaservizi.agenziaentrate.gov.it',
                'referer': f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-web/?v={unix_timestamp()}',
                'accept': 'application/json, text/plain, */*',
                'x-b2bcookie': self.headers_token.get('x-b2bcookie'),
                'x-token': self.headers_token.get('x-token'),
                'User-Agent': DEFAULT_USER_AGENT
            }
            
            r = self.session.get(url_fattura, headers=headers, stream=True, timeout=60, verify=False)
            
            if r.status_code != 200:
                self.download_stats.add_errore(tipo_doc, id_fattura, f"HTTP {r.status_code}")
                self.logger.error(f"Errore download {id_fattura}: HTTP {r.status_code}")
                return False
            
            # Estrai nome originale ESATTO
            nome_originale_fattura = self.extract_original_filename(r.headers.get('content-disposition'))
            if not nome_originale_fattura:
                nome_originale_fattura = f"{id_fattura}.xml"
            
            self.logger.info(f"Download {id_fattura} -> Nome originale: {nome_originale_fattura}")
            
            # Salva contenuto in memoria
            fattura_content = r.content
            
            # Determina estensione
            ext = '.p7m' if nome_originale_fattura.lower().endswith('.p7m') else '.xml'
            
            # IMPORTANTE: Salva in TUTTE le directory create
            paths = {}
            saved_count = 0
            for dir_type, directory in dirs_to_create:
                if dir_type == 'originali':
                    # Salva con nome originale
                    path_originale = directory / nome_originale_fattura
                    with open(path_originale, 'wb') as f:
                        f.write(fattura_content)
                    paths['originale_fattura'] = str(path_originale.relative_to(temp_dir))
                    self.logger.info(f"✅ Salvato in originali: {path_originale.name}")
                    saved_count += 1
                    
                elif dir_type == 'id_sdi':
                    # Salva con ID SDI
                    path_id_sdi = directory / f"{id_fattura}_FATTURA{ext}"
                    with open(path_id_sdi, 'wb') as f:
                        f.write(fattura_content)
                    paths['id_sdi_fattura'] = str(path_id_sdi.relative_to(temp_dir))
                    self.logger.info(f"✅ Salvato in id_sdi: {path_id_sdi.name}")
                    saved_count += 1
            
            self.logger.info(f"File salvato in {saved_count} strutture per {id_fattura}")
            
            # Download metadato se configurato
            if self.config['configurazione_download'].get('download_metadati', True):
                url_metadato = f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fatture/file/{id_fattura}?tipoFile=FILE_METADATI&download=1&v={unix_timestamp()}'
                
                r = self.session.get(url_metadato, headers=headers, stream=True, timeout=60, verify=False)
                
                if r.status_code == 200:
                    # Estrai nome originale metadato
                    nome_originale_metadato = self.extract_original_filename(r.headers.get('content-disposition'))
                    if not nome_originale_metadato:
                        nome_originale_metadato = f"{nome_originale_fattura}_METADATO.xml"
                    
                    metadato_content = r.content
                    
                    # Salva metadato in TUTTE le directory create
                    for dir_type, directory in dirs_to_create:
                        if dir_type == 'originali':
                            # Nome metadato basato su nome originale fattura
                            nome_metadato_custom = f"{nome_originale_fattura}_METADATO.xml"
                            path_metadato = directory / nome_metadato_custom
                            with open(path_metadato, 'wb') as f:
                                f.write(metadato_content)
                            paths['originale_metadato'] = str(path_metadato.relative_to(temp_dir))
                            self.logger.debug(f"Metadato salvato in originali: {path_metadato.name}")
                            
                        elif dir_type == 'id_sdi':
                            # Nome metadato con ID SDI
                            path_metadato = directory / f"{id_fattura}_METADATO.xml"
                            with open(path_metadato, 'wb') as f:
                                f.write(metadato_content)
                            paths['id_sdi_metadato'] = str(path_metadato.relative_to(temp_dir))
                            self.logger.debug(f"Metadato salvato in id_sdi: {path_metadato.name}")
                    
                    # Registra nel registry
                    if self.registry:
                        self.registry.add_file(id_fattura, nome_originale_metadato, "metadato", paths)
            
            # Registra fattura nel registry
            if self.registry:
                self.registry.add_file(id_fattura, nome_originale_fattura, "fattura", paths)
                self.registry.save()
            
            self.download_stats.add_scaricata(tipo_doc, id_fattura)
            self.logger.info(f"✅ Download completato: {id_fattura} -> {nome_originale_fattura}")
            return True
            
        except Exception as e:
            self.logger.error(f"Errore download completo {id_fattura}: {e}")
            self.download_stats.add_errore(tipo_doc, id_fattura, str(e))
            return False
    
    def decode_p7m_duplicato(self, source_dir: Path):
        """Decodifica P7M mantenendo entrambe le versioni (originale e ID_SDI)"""
        try:
            struttura_file = self.config['configurazione_download'].get('struttura_file', 'ENTRAMBE')
            dirs_to_process = []
            
            if struttura_file in ['ENTRAMBE', 'ORIGINALE']:
                dir_originali = source_dir / self.config['directory_sistema'].get('struttura_originali', 'originali')
                if dir_originali.exists():
                    dirs_to_process.append(dir_originali)
            
            if struttura_file in ['ENTRAMBE', 'ID_SDI']:
                dir_id_sdi = source_dir / self.config['directory_sistema'].get('struttura_id_sdi', 'id_sdi')
                if dir_id_sdi.exists():
                    dirs_to_process.append(dir_id_sdi)
            
            decoded_count = 0
            
            for directory in dirs_to_process:
                for p7m_file in directory.glob("*.p7m"):
                    try:
                        # Determina nome output
                        if p7m_file.name.endswith('.xml.p7m'):
                            # Rimuove solo .p7m finale
                            xml_name = p7m_file.name[:-4]
                        else:
                            # Rimuove .p7m e aggiunge .xml
                            xml_name = p7m_file.stem + '.xml'
                        
                        xml_path = directory / xml_name
                        
                        # Decodifica con OpenSSL
                        result = subprocess.run(
                            ['openssl', 'cms', '-verify', '-noverify', '-inform', 'DER', 
                             '-in', str(p7m_file), '-out', str(xml_path)],
                            capture_output=True, timeout=30
                        )
                        
                        if xml_path.exists() and xml_path.stat().st_size > 0:
                            decoded_count += 1
                            self.logger.info(f"Decodificato: {p7m_file.name} -> {xml_name}")
                        
                    except Exception as e:
                        self.logger.warning(f"Errore decodifica {p7m_file.name}: {e}")
            
            if decoded_count > 0:
                print(f"✅ Decodificati {decoded_count} file P7M")
            
        except Exception as e:
            self.logger.error(f"Errore decodifica P7M: {e}")
    
    def organize_files(self, source_dir: Path, client_data: Dict):
        """
        Organizza file nella struttura definitiva con corretta distinzione EMESSE/RICEVUTE
        VERSIONE CORRETTA: usa il registry per mappare nomi originali a ID_SDI
        """
        try:
            # Nome cartella finale
            client_folder = create_client_folder_name(
                client_data.get('nome_azienda', 'SCONOSCIUTO'),
                client_data.get('partita_iva_diretta', '00000000000'),
                client_data.get('codice_fiscale', 'XXXXXXXXXXXXXXXX')
            )
            
            output_base = Path(self.config['directory_sistema']['output_base'])
            struttura_file = self.config['configurazione_download'].get('struttura_file', 'ENTRAMBE')
            
            organized_count = 0
            errors_count = 0
            
            # Carica le liste JSON per determinare il tipo di fattura
            liste_dir = Path(self.config['directory_sistema'].get('liste_fatture', 'liste_fatture_json'))
            mapping_fatture = {}  # id_sdi -> tipo_fattura
            
            # Costruisci mapping ID_SDI -> tipo fattura dalle liste JSON
            self.logger.info("Caricamento mapping fatture dalle liste JSON...")
            for json_file in liste_dir.glob(f"{client_folder}_*.json"):
                try:
                    with open(json_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        fatture = data.get('fatture', [])
                        
                        # Determina tipo dalla filename
                        if 'emesse' in json_file.name:
                            tipo = 'EMESSE'
                        elif 'transfrontaliere_emesse' in json_file.name:
                            tipo = 'EMESSE'
                        elif 'ricevute' in json_file.name:
                            tipo = 'RICEVUTE'
                        elif 'transfrontaliere_ricevute' in json_file.name:
                            tipo = 'RICEVUTE'
                        elif 'messe_disposizione' in json_file.name:
                            tipo = 'RICEVUTE'
                        else:
                            tipo = 'RICEVUTE'
                        
                        for fattura in fatture:
                            id_sdi = fattura.get('tipoInvio', '') + fattura.get('idFattura', '')
                            if id_sdi:
                                mapping_fatture[id_sdi] = tipo
                                
                        self.logger.info(f"Caricato mapping da {json_file.name}: {len(fatture)} fatture di tipo {tipo}")
                        
                except Exception as e:
                    self.logger.warning(f"Errore lettura JSON {json_file}: {e}")
            
            # NUOVO: Carica anche il registry per mappare nomi originali -> ID_SDI
            registry_mapping = {}  # nome_originale -> id_sdi
            if self.registry and hasattr(self.registry, 'data'):
                registry_mapping = self.registry.data.get('mapping_nomi', {})
                self.logger.info(f"Caricato registry con {len(registry_mapping)} mappings nome->ID_SDI")
            
            # DEBUG: Mostra quante EMESSE vs RICEVUTE nel mapping
            emesse_count = sum(1 for v in mapping_fatture.values() if v == 'EMESSE')
            ricevute_count = sum(1 for v in mapping_fatture.values() if v == 'RICEVUTE')
            print(f"\n📊 Mapping: {emesse_count} EMESSE, {ricevute_count} RICEVUTE")
            
            # Processa entrambe le strutture se configurato
            dirs_to_process = []
            if struttura_file in ['ENTRAMBE', 'ORIGINALE']:
                dir_originali = source_dir / self.config['directory_sistema'].get('struttura_originali', 'originali')
                if dir_originali.exists():
                    dirs_to_process.append(('originali', dir_originali))
            
            if struttura_file in ['ENTRAMBE', 'ID_SDI']:
                dir_id_sdi = source_dir / self.config['directory_sistema'].get('struttura_id_sdi', 'id_sdi')
                if dir_id_sdi.exists():
                    dirs_to_process.append(('id_sdi', dir_id_sdi))
            
            print(f"\n📂 Organizzazione file in corso...")
            print(f"   Mapping caricato: {len(mapping_fatture)} fatture identificate")
            
            # Contatori per statistiche
            stats_detail = {
                'EMESSE': {'originali': 0, 'id_sdi': 0},
                'RICEVUTE': {'originali': 0, 'id_sdi': 0}
            }
            
            for struct_type, source_subdir in dirs_to_process:
                for file_path in source_subdir.glob('*'):
                    if not file_path.is_file():
                        continue
                    
                    try:
                        # Estrai ID_SDI dal nome file
                        id_sdi = None
                        
                        # Metodo 1: Se siamo in id_sdi/, il nome file contiene già l'ID_SDI
                        if struct_type == 'id_sdi':
                            if '_FATTURA' in file_path.name or '_METADATO' in file_path.name:
                                # Estrai ID_SDI dal nome (tutto prima di _FATTURA o _METADATO)
                                if '_FATTURA' in file_path.name:
                                    id_sdi = file_path.name.split('_FATTURA')[0]
                                elif '_METADATO' in file_path.name:
                                    id_sdi = file_path.name.split('_METADATO')[0]
                        
                        # Metodo 2: Se siamo in originali/, usa il registry per trovare l'ID_SDI
                        elif struct_type == 'originali':
                            # Prima cerca nel registry con il nome esatto
                            if file_path.name in registry_mapping:
                                id_sdi = registry_mapping[file_path.name]
                                self.logger.debug(f"Trovato in registry: {file_path.name} -> {id_sdi}")
                            else:
                                # Se è un metadato, prova a trovare il file principale
                                if '_METADATO' in file_path.name:
                                    base_name = file_path.name.replace('_METADATO.xml', '').replace('.xml_METADATO.xml', '.xml')
                                    if base_name in registry_mapping:
                                        id_sdi = registry_mapping[base_name]
                                
                                # Ultimo tentativo: cerca pattern ID_SDI nel nome
                                if not id_sdi:
                                    match = re.search(r'(IT\d{11}_[\w]+)', file_path.stem)
                                    if match:
                                        id_sdi = match.group(1)
                        
                        # Determina direzione usando il mapping
                        direzione = 'RICEVUTE'  # Default
                        if id_sdi and id_sdi in mapping_fatture:
                            direzione = mapping_fatture[id_sdi]
                            self.logger.debug(f"File {file_path.name} -> ID_SDI: {id_sdi} -> Tipo: {direzione}")
                        else:
                            # Se non trovato, log di warning
                            if id_sdi:
                                self.logger.warning(f"ID_SDI {id_sdi} non trovato nel mapping per {file_path.name}")
                            else:
                                self.logger.warning(f"ID_SDI non estratto per {file_path.name}, uso default RICEVUTE")
                        
                        # Determina anno dalla fattura XML
                        anno = datetime.now().year
                        if file_path.suffix.lower() == '.xml' and 'METADATO' not in file_path.name.upper():
                            anno_estratto = extract_anno_from_xml(file_path)
                            if anno_estratto:
                                anno = anno_estratto
                                self.logger.debug(f"Anno estratto da {file_path.name}: {anno}")
                        
                        # Per i metadati, usa l'anno della fattura associata
                        elif 'METADATO' in file_path.name.upper():
                            # Cerca il file fattura associato
                            fattura_name = file_path.name.replace('_METADATO', '').replace('METADATO', '')
                            if fattura_name.endswith('.xml'):
                                fattura_name = fattura_name[:-4]
                            
                            for fattura_path in source_subdir.glob(f"{fattura_name}*.xml"):
                                if 'METADATO' not in fattura_path.name.upper():
                                    anno_estratto = extract_anno_from_xml(fattura_path)
                                    if anno_estratto:
                                        anno = anno_estratto
                                        self.logger.debug(f"Anno per metadato estratto da fattura associata: {anno}")
                                    break
                        
                        # Crea struttura finale preservando originali/id_sdi
                        dest_base = output_base / client_folder / direzione / str(anno) / struct_type
                        
                        # Determina sottocartella
                        if file_path.suffix.lower() == '.p7m':
                            subdir = dest_base / 'p7m_originali'
                        elif 'METADATO' in file_path.name.upper():
                            subdir = dest_base / 'metadati'
                        elif file_path.suffix.lower() == '.xml':
                            subdir = dest_base / 'xml_decodificati'
                        else:
                            subdir = dest_base / 'altri'
                        
                        subdir.mkdir(parents=True, exist_ok=True)
                        
                        # Copia file
                        dest_file = subdir / file_path.name
                        shutil.copy2(file_path, dest_file)
                        organized_count += 1
                        
                        # Aggiorna statistiche
                        stats_detail[direzione][struct_type] += 1
                        
                        self.logger.info(f"Organizzato: {file_path.name} -> {direzione}/{anno}/{struct_type}")
                        
                    except Exception as e:
                        errors_count += 1
                        self.logger.error(f"Errore organizzazione {file_path.name}: {e}")
            
            # Report finale
            print(f"\n✅ Organizzazione completata:")
            print(f"   File organizzati: {organized_count}")
            
            print(f"\n📊 Dettaglio file organizzati:")
            for direzione in ['EMESSE', 'RICEVUTE']:
                print(f"   {direzione}:")
                for struct in ['originali', 'id_sdi']:
                    count = stats_detail[direzione][struct]
                    print(f"      {struct}: {count} file")
            
            if errors_count > 0:
                print(f"   ⚠️ Errori: {errors_count}")
            print(f"   📂 Directory: {output_base / client_folder}")
            
            # Verifica finale strutture create
            print(f"\n🔍 Verifica strutture create:")
            for direzione in ['EMESSE', 'RICEVUTE']:
                dir_path = output_base / client_folder / direzione
                if dir_path.exists():
                    for anno_dir in dir_path.glob('*'):
                        if anno_dir.is_dir():
                            originali_exists = (anno_dir / 'originali').exists()
                            id_sdi_exists = (anno_dir / 'id_sdi').exists()
                            
                            if originali_exists or id_sdi_exists:
                                print(f"   {direzione}/{anno_dir.name}:")
                                if originali_exists:
                                    count = sum(1 for _ in (anno_dir / 'originali').rglob('*') if _.is_file())
                                    print(f"      ✅ originali: {count} file")
                                if id_sdi_exists:
                                    count = sum(1 for _ in (anno_dir / 'id_sdi').rglob('*') if _.is_file())
                                    print(f"      ✅ id_sdi: {count} file")
            
        except Exception as e:
            self.logger.error(f"Errore organizzazione file: {e}")
            print(f"❌ Errore durante l'organizzazione: {e}")

    
    def process_client(self, client_id, client_data, data_inizio, data_fine):
        """Processa un singolo cliente - VERSIONE CON DECODIFICA FINALE"""
        print(f"\n{'='*60}")
        print(f"Cliente: {client_data.get('nome_azienda', 'N/D')}")
        print(f"P.IVA: {client_data.get('partita_iva_diretta', 'N/D')}")
        print(f"CF: {client_data.get('codice_fiscale', 'N/D')}")
        print(f"{'='*60}")
        
        # Seleziona cliente
        if not self.select_client(client_data):
            return
        
        # Setup headers
        if not self.setup_headers():
            return
        
        # Nome cartella cliente
        client_folder = create_client_folder_name(
            client_data.get('nome_azienda', 'SCONOSCIUTO'),
            client_data.get('partita_iva_diretta', '00000000000'),
            client_data.get('codice_fiscale', 'XXXXXXXXXXXXXXXX')
        )
        
        # Directory temporanea
        temp_dir = Path(self.config['directory_sistema']['input_temp']) / client_folder
        temp_dir.mkdir(parents=True, exist_ok=True)
        
        # Inizializza registry per questo cliente
        registry_dir = Path(self.config['directory_sistema'].get('registri', 'registri_file')) / client_folder
        registry_dir.mkdir(parents=True, exist_ok=True)
        self.registry = FileRegistry(registry_dir / f'registry_{data_inizio}_{data_fine}.json')
        
        # FASE 1: Download liste JSON
        print("\n📋 FASE 1: Download liste fatture")
        
        tipi = [
            ('emesse', None),
            ('ricevute', 'ricezione'),
            ('ricevute', 'emissione'),
            ('transfrontaliere_emesse', None),
            ('transfrontaliere_ricevute', None),
            ('messe_disposizione', None)
        ]
        
        liste_json = []
        for tipo, ricerca in tipi:
            json_path = self.download_lista_fatture(
                tipo, data_inizio, data_fine, client_folder, 
                ricerca if ricerca else 'ricezione'
            )
            if json_path:
                liste_json.append(json_path)
        
        # FASE 2: Download fatture
        print("\n📥 FASE 2: Download fatture e metadati")
        
        for json_path in liste_json:
            try:
                with open(json_path, 'r') as f:
                    data = json.load(f)
                
                fatture = data.get('fatture', [])
                if not fatture:
                    continue
                
                # Determina tipo
                if 'emesse' in json_path.name:
                    tipo_doc = 'EMESSE'
                elif 'transfrontaliere' in json_path.name:
                    if 'emesse' in json_path.name:
                        tipo_doc = 'TRANSFRONTALIERE_EMESSE'
                    else:
                        tipo_doc = 'TRANSFRONTALIERE_RICEVUTE'
                elif 'messe_disposizione' in json_path.name:
                    tipo_doc = 'MESSE_DISPOSIZIONE'
                else:
                    tipo_doc = 'RICEVUTE'
                
                print(f"\n📂 Elaborazione {len(fatture)} fatture {tipo_doc}...")
                
                # Controlla quali file esistono già
                to_download = []
                skipped_count = 0
                
                for fattura in fatture:
                    id_fattura = fattura.get('tipoInvio', '') + fattura.get('idFattura', '')
                    if not id_fattura:
                        continue
                    
                    # Controllo file esistenti
                    if self.check_file_exists(id_fattura, temp_dir):
                        self.download_stats.add_gia_presente(tipo_doc, id_fattura)
                        skipped_count += 1
                    else:
                        to_download.append(fattura)
                
                if skipped_count > 0:
                    print(f"ℹ️ {skipped_count} file già presenti, scarico {len(to_download)} nuovi")
                
                # Download solo quelli mancanti
                for fattura in tqdm(to_download, desc=f"Download {tipo_doc}"):
                    id_fattura = fattura.get('tipoInvio', '') + fattura.get('idFattura', '')
                    self.download_fattura_completa(id_fattura, temp_dir, tipo_doc)
            
            except Exception as e:
                self.logger.error(f"Errore processamento lista {json_path}: {e}")
        
        # FASE 3: Decodifica P7M nella cartella temporanea
        if self.config['configurazione_download'].get('decodifica_p7m_duplicata', True):
            print("\n🔓 FASE 3: Decodifica file P7M (cartella temporanea)")
            self.decode_p7m_duplicato(temp_dir)
        
        # FASE 4: Organizzazione finale
        print("\n📁 FASE 4: Organizzazione file")
        self.organize_files(temp_dir, client_data)
        
        # FASE 5: Decodifica P7M nelle cartelle finali
        if self.config['configurazione_download'].get('decodifica_p7m_duplicata', True):
            print("\n🔓 FASE 5: Decodifica file P7M (cartelle finali)")
            output_base = Path(self.config['directory_sistema']['output_base'])
            client_output = output_base / client_folder
            if client_output.exists():
                self.decode_p7m_finale(client_output)
    
    def run(self, data_inizio, data_fine):
        """Esecuzione principale"""
        start_time = time.time()
        
        # Login
        if not self.login():
            return
        
        # Dividi in trimestri
        trimestri = divide_in_trimestri(data_inizio, data_fine)
        print(f"Periodo diviso in {len(trimestri)} trimestri")
        
        # Reset statistiche
        self.download_stats = DownloadStats()
        
        # Per ogni trimestre
        for trim_inizio, trim_fine in trimestri:
            print(f"\n📅 Trimestre: {trim_inizio} - {trim_fine}")
            
            # Per ogni cliente
            for client_id, client_data in self.config.get('portfolio_clienti', {}).items():
                if client_data.get('attivo', True):
                    self.process_client(client_id, client_data, trim_inizio, trim_fine)
        
        # Stampa riepilogo finale
        self.download_stats.print_summary()
        
        elapsed = time.time() - start_time
        print(f"\n✅ Elaborazione completata in {elapsed:.2f} secondi")
    
    def test(self):
        """Test configurazione e connessione"""
        print("\n🔬 TEST SISTEMA v12.01")
        print("="*50)
        
        # Test config
        print("1. Configurazione:", end=" ")
        if self.config:
            print("✅ Caricata")
            print(f"   Struttura file: {self.config['configurazione_download'].get('struttura_file', 'ENTRAMBE')}")
            gestione_file = self.config.get('configurazione_download', {}).get('gestione_file', {})
            print(f"   Salta file esistenti: {gestione_file.get('salta_file_esistenti', True)}")
        else:
            print("❌ Errore")
            return
        
        # Test clienti
        clienti = self.config.get('portfolio_clienti', {})
        attivi = [c for c in clienti.values() if c.get('attivo', True)]
        print(f"2. Clienti attivi: {len(attivi)}")
        
        for client in attivi:
            print(f"   - {client.get('nome_azienda', 'N/D')} (P.IVA: {client.get('partita_iva_diretta', 'N/D')})")
        
        print("\nâœ… Test completato!")

    def decode_p7m_finale(self, output_dir: Path):
        """
        Decodifica file P7M nelle cartelle finali organizzate
        Cerca in tutte le sottocartelle p7m_originali e decodifica in xml_decodificati
        """
        try:
            decoded_count = 0
            errors_count = 0
            
            print("\n🔓 Decodifica P7M nelle cartelle finali...")
            
            # Cerca tutte le cartelle p7m_originali
            for p7m_dir in output_dir.rglob('p7m_originali'):
                if not p7m_dir.is_dir():
                    continue
                
                # Determina la cartella xml_decodificati parallela
                # p7m_dir è qualcosa come .../EMESSE/2025/id_sdi/p7m_originali
                # xml_dir dovrebbe essere .../EMESSE/2025/id_sdi/xml_decodificati
                parent_dir = p7m_dir.parent  # Questo è .../EMESSE/2025/id_sdi o .../EMESSE/2025/originali
                xml_dir = parent_dir / 'xml_decodificati'
                xml_dir.mkdir(parents=True, exist_ok=True)
                
                # Decodifica ogni file P7M
                for p7m_file in p7m_dir.glob("*.p7m"):
                    try:
                        # Determina nome output
                        if p7m_file.name.endswith('.xml.p7m'):
                            # Rimuove solo .p7m finale, mantiene .xml
                            xml_name = p7m_file.name[:-4]  # Rimuove .p7m
                        else:
                            # Sostituisce .p7m con .xml
                            xml_name = p7m_file.stem + '.xml'
                        
                        xml_path = xml_dir / xml_name
                        
                        # Se il file XML esiste già, salta
                        if xml_path.exists() and xml_path.stat().st_size > 0:
                            self.logger.debug(f"XML già esistente, salto: {xml_name}")
                            continue
                        
                        # Decodifica con OpenSSL
                        result = subprocess.run(
                            ['openssl', 'cms', '-verify', '-noverify', '-inform', 'DER', 
                             '-in', str(p7m_file), '-out', str(xml_path)],
                            capture_output=True, 
                            timeout=30
                        )
                        
                        if xml_path.exists() and xml_path.stat().st_size > 0:
                            decoded_count += 1
                            self.logger.info(f"Decodificato: {p7m_file.name} -> {xml_name}")
                        else:
                            errors_count += 1
                            self.logger.warning(f"Decodifica fallita per {p7m_file.name}")
                            # Se la decodifica fallisce, rimuovi il file vuoto
                            if xml_path.exists():
                                xml_path.unlink()
                        
                    except subprocess.TimeoutExpired:
                        errors_count += 1
                        self.logger.error(f"Timeout decodifica {p7m_file.name}")
                    except Exception as e:
                        errors_count += 1
                        self.logger.error(f"Errore decodifica {p7m_file.name}: {e}")
            
            if decoded_count > 0:
                print(f"✅ Decodificati {decoded_count} file P7M nelle cartelle finali")
            if errors_count > 0:
                print(f"⚠️ Errori decodifica: {errors_count}")
            
            return decoded_count, errors_count
            
        except Exception as e:
            self.logger.error(f"Errore decodifica P7M finale: {e}")
            print(f"❌ Errore durante la decodifica finale: {e}")
            return 0, 0


def main():
    parser = argparse.ArgumentParser(description='Sistema Fatture AdE v12.01')
    
    parser.add_argument('command', choices=['full', 'test'], help='Comando da eseguire')
    parser.add_argument('data_inizio', nargs='?', help='Data inizio (DD/MM/YYYY)')
    parser.add_argument('data_fine', nargs='?', help='Data fine (DD/MM/YYYY)')
    parser.add_argument('--config', default=CONFIG_FILE, help='File configurazione')
    
    args = parser.parse_args()
    
    sistema = SistemaFattureV12(args.config)
    
    if args.command == 'full':
        if not args.data_inizio or not args.data_fine:
            print("❌ Specificare data_inizio e data_fine")
            sys.exit(1)
        
        # Converti date
        try:
            data_inizio = datetime.strptime(args.data_inizio, "%d/%m/%Y").strftime("%d%m%Y")
            data_fine = datetime.strptime(args.data_fine, "%d/%m/%Y").strftime("%d%m%Y")
        except ValueError:
            print("❌ Formato data non valido. Usa DD/MM/YYYY")
            sys.exit(1)
        
        sistema.run(data_inizio, data_fine)
    
    elif args.command == 'test':
        sistema.test()

if __name__ == "__main__":
    main()