#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sistema di Gestione Invii Massivi - Agenzia delle Entrate
Versione: 3.2.0 - FIXED
Autore: Sistema Automatizzato
Data: 2025-08-16
"""

import json
import os
import sys
import time
import re
import base64
import zipfile
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import pytz
from dateutil.parser import parse
import xml.etree.ElementTree as ET
from xml.dom import minidom

# Disabilita warnings SSL
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ============================================================================
# MODULO: Configurazione e Utility
# ============================================================================

class Config:
    """Gestione configurazione sistema"""
    
    def __init__(self, config_path="config/config_ade_system.json"):
        self.config_path = config_path
        self.config = self.load_config()
        self.ensure_directories()
    
    def load_config(self) -> dict:
        """Carica configurazione da file JSON"""
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"❌ File di configurazione non trovato: {self.config_path}")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"❌ Errore nel parsing del file di configurazione: {e}")
            sys.exit(1)
    
    def ensure_directories(self):
        """Crea le directory necessarie se non esistono"""
        dirs = [
            'logs',
            'downloads',
            'xml_requests',
            'xml_requests/archive',
            'reports',
            'temp',
            'aziende_processate'
        ]
        for dir_path in dirs:
            Path(dir_path).mkdir(parents=True, exist_ok=True)
    
    def get_active_clients(self) -> Dict:
        """Restituisce solo i clienti attivi"""
        return {
            k: v for k, v in self.config['portfolio_clienti'].items()
            if v.get('attivo', False)
        }
    
    def get_clients_with_corrispettivi(self) -> Dict:
        """Restituisce solo i clienti con corrispettivi abilitati"""
        return {
            k: v for k, v in self.config['portfolio_clienti'].items()
            if v.get('attivo', False) and v.get('corrispettivi_abilitati', False)
        }

class Logger:
    """Sistema di logging semplificato"""
    
    def __init__(self, log_file="logs/ade_system.log"):
        self.log_file = log_file
        self.ensure_log_dir()
    
    def ensure_log_dir(self):
        Path(os.path.dirname(self.log_file)).mkdir(parents=True, exist_ok=True)
    
    def log(self, message: str, level: str = "INFO", indent: int = 0):
        """Scrive un messaggio nel log"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] [{level}] {'  ' * indent}{message}"
        
        # Scrivi su file
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(log_message + "\n")
        
        # Stampa a console con colori e indentazione
        indent_str = "  " * indent
        if level == "ERROR":
            print(f"{indent_str}❌ {message}")
        elif level == "WARNING":
            print(f"{indent_str}⚠️  {message}")
        elif level == "SUCCESS":
            print(f"{indent_str}✅ {message}")
        else:
            print(f"{indent_str}ℹ️  {message}")

# ============================================================================
# MODULO: Gestione Sessione ADE
# ============================================================================

class ADESession:
    """Gestione della sessione con il portale dell'Agenzia delle Entrate"""
    
    def __init__(self, config: Config, logger: Logger):
        self.config = config
        self.logger = logger
        self.session = requests.Session()
        self.setup_session()
        self.p_auth = None
        self.xb2bcookie = None
        self.xtoken = None
        self.current_client = None
        self.current_piva = None
    
    def setup_session(self):
        """Configura la sessione HTTP"""
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Connection': 'keep-alive'
        })
    
    def unix_time(self) -> str:
        """Genera timestamp Unix in millisecondi"""
        dt = datetime.now(tz=pytz.utc)
        return str(int(dt.timestamp() * 1000))
    
    def login(self) -> bool:
        """Effettua il login al portale"""
        try:
            creds = self.config.config['credenziali_ade']
            
            # Setup cookies iniziali
            cookie_obj1 = requests.cookies.create_cookie(
                domain='ivaservizi.agenziaentrate.gov.it',
                name='LFR_SESSION_STATE_20159',
                value='expired'
            )
            self.session.cookies.set_cookie(cookie_obj1)
            
            cookie_obj2 = requests.cookies.create_cookie(
                domain='ivaservizi.agenziaentrate.gov.it',
                name='LFR_SESSION_STATE_10811916',
                value=self.unix_time()
            )
            self.session.cookies.set_cookie(cookie_obj2)
            
            # Homepage
            self.logger.log("Connessione alla homepage...")
            r = self.session.get('https://ivaservizi.agenziaentrate.gov.it/portale/web/guest', verify=False)
            
            # Login
            self.logger.log("Effettuo il login...")
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
                data=payload
            )
            
            # Estrai p_auth token
            liferay_match = re.findall(r"Liferay.authToken = '.*';", r.text)
            if liferay_match:
                self.p_auth = liferay_match[0].replace("Liferay.authToken = '", "").replace("';", "")
                self.logger.log("Login effettuato con successo", "SUCCESS")
                return True
            else:
                self.logger.log("Impossibile ottenere il token di autenticazione", "ERROR")
                return False
                
        except Exception as e:
            self.logger.log(f"Errore durante il login: {str(e)}", "ERROR")
            return False
    
    def select_client(self, client_data: dict) -> bool:
        """Seleziona un cliente per l'operazione"""
        try:
            cf_studio = self.config.config['credenziali_ade']['codice_fiscale_studio']
            cf_cliente = client_data['codice_fiscale']
            piva = client_data['partita_iva_diretta']
            profilo = client_data.get('profilo_accesso', 1)
            
            self.logger.log(f"Selezione cliente: {client_data['nome_azienda']} (P.IVA: {piva})", indent=1)
            
            # API endpoint per selezione
            r = self.session.get('https://ivaservizi.agenziaentrate.gov.it/dp/api?v=' + self.unix_time())
            
            if profilo == 1:  # Delega Diretta
                payload = {'cf_inserito': cf_cliente}
                r = self.session.post(
                    f'https://ivaservizi.agenziaentrate.gov.it/portale/scelta-utenza-lavoro?p_auth={self.p_auth}&p_p_id=SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet&p_p_lifecycle=1&p_p_state=normal&p_p_mode=view&p_p_col_id=column-1&p_p_col_count=1&_SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet_javax.portlet.action=delegaDirettaAction',
                    data=payload
                )
                
                payload = {'cf_inserito': cf_cliente, 'sceltapiva': piva}
                r = self.session.post(
                    f'https://ivaservizi.agenziaentrate.gov.it/portale/scelta-utenza-lavoro?p_auth={self.p_auth}&p_p_id=SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet&p_p_lifecycle=1&p_p_state=normal&p_p_mode=view&p_p_col_id=column-1&p_p_col_count=1&_SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet_javax.portlet.action=delegaDirettaAction',
                    data=payload
                )
            
            # Ottieni token per servizi
            r = self.session.get('https://ivaservizi.agenziaentrate.gov.it/ser/api/fatture/v1/ul/me/adesione/stato/')
            
            headers_token = {
                'x-xss-protection': '1; mode=block',
                'strict-transport-security': 'max-age=16070400; includeSubDomains',
                'x-content-type-options': 'nosniff',
                'x-frame-options': 'deny'
            }
            
            r = self.session.get(
                f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/sc/tokenB2BCookie/get?v={self.unix_time()}',
                headers=headers_token
            )
            
            self.xb2bcookie = r.headers.get('x-b2bcookie')
            self.xtoken = r.headers.get('x-token')
            
            if self.xb2bcookie and self.xtoken:
                self.current_client = client_data
                self.current_piva = piva
                
                # Accetta disclaimer
                self.session.get(
                    f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/disclaimer/accetta?v={self.unix_time()}',
                    headers=headers_token
                )
                
                return True
            
            return False
            
        except Exception as e:
            self.logger.log(f"Errore nella selezione del cliente: {str(e)}", "ERROR", indent=1)
            return False
    
    def logout(self):
        """Effettua il logout"""
        try:
            self.session.get('https://ivaservizi.agenziaentrate.gov.it/portale/c/portal/logout')
            self.logger.log("Logout effettuato")
        except:
            pass

# ============================================================================
# MODULO: Costruttore Richieste XML
# ============================================================================

class XMLRequestBuilder:
    """Costruisce le richieste XML secondo lo schema XSD"""
    
    TIPI_CORRISPETTIVI = ['RT', 'MC', 'DA', 'DC', 'RC']
    
    def __init__(self, logger: Logger):
        self.logger = logger
        self.namespace = "http://www.sogei.it/InputPubblico"
    
    def create_fatture_emesse(self, piva: str, data_da: str, data_a: str, tipo_flusso: str = "ALL") -> str:
        """Crea XML per richiesta fatture emesse"""
        root = self._create_root()
        tipo_richiesta = ET.SubElement(root, f"{{{self.namespace}}}TipoRichiesta")
        fatture = ET.SubElement(tipo_richiesta, f"{{{self.namespace}}}Fatture")
        
        ET.SubElement(fatture, f"{{{self.namespace}}}Richiesta").text = "FATT"
        
        elenco_piva = ET.SubElement(fatture, f"{{{self.namespace}}}ElencoPiva")
        ET.SubElement(elenco_piva, f"{{{self.namespace}}}Piva").text = piva
        
        ET.SubElement(fatture, f"{{{self.namespace}}}TipoRicerca").text = "PUNTUALE"
        
        fatture_emesse = ET.SubElement(fatture, f"{{{self.namespace}}}FattureEmesse")
        data_emissione = ET.SubElement(fatture_emesse, f"{{{self.namespace}}}DataEmissione")
        ET.SubElement(data_emissione, f"{{{self.namespace}}}Da").text = data_da
        ET.SubElement(data_emissione, f"{{{self.namespace}}}A").text = data_a
        
        flusso = ET.SubElement(fatture_emesse, f"{{{self.namespace}}}Flusso")
        ET.SubElement(flusso, f"{{{self.namespace}}}Tutte").text = "ALL"
        
        ET.SubElement(fatture_emesse, f"{{{self.namespace}}}Ruolo").text = "CEDENTE"
        
        return self._prettify(root)
    
    def create_fatture_ricevute(self, piva: str, data_da: str, data_a: str, tipo_flusso: str = "ALL") -> str:
        """Crea XML per richiesta fatture ricevute"""
        root = self._create_root()
        tipo_richiesta = ET.SubElement(root, f"{{{self.namespace}}}TipoRichiesta")
        fatture = ET.SubElement(tipo_richiesta, f"{{{self.namespace}}}Fatture")
        
        ET.SubElement(fatture, f"{{{self.namespace}}}Richiesta").text = "FATT"
        
        elenco_piva = ET.SubElement(fatture, f"{{{self.namespace}}}ElencoPiva")
        ET.SubElement(elenco_piva, f"{{{self.namespace}}}Piva").text = piva
        
        ET.SubElement(fatture, f"{{{self.namespace}}}TipoRicerca").text = "PUNTUALE"
        
        fatture_ricevute = ET.SubElement(fatture, f"{{{self.namespace}}}FattureRicevute")
        data_ricezione = ET.SubElement(fatture_ricevute, f"{{{self.namespace}}}DataRicezione")
        ET.SubElement(data_ricezione, f"{{{self.namespace}}}Da").text = data_da
        ET.SubElement(data_ricezione, f"{{{self.namespace}}}A").text = data_a
        
        flusso = ET.SubElement(fatture_ricevute, f"{{{self.namespace}}}Flusso")
        ET.SubElement(flusso, f"{{{self.namespace}}}Tutte").text = "ALL"
        
        ET.SubElement(fatture_ricevute, f"{{{self.namespace}}}Ruolo").text = "CESSIONARIO"
        
        return self._prettify(root)
    
    def create_corrispettivi(self, piva: str, data_da: str, data_a: str, tipo_corrispettivo: str) -> str:
        """Crea XML per richiesta corrispettivi"""
        root = self._create_root()
        tipo_richiesta = ET.SubElement(root, f"{{{self.namespace}}}TipoRichiesta")
        corrispettivi = ET.SubElement(tipo_richiesta, f"{{{self.namespace}}}Corrispettivi")
        
        ET.SubElement(corrispettivi, f"{{{self.namespace}}}Richiesta").text = "CORR"
        
        data_rilevazione = ET.SubElement(corrispettivi, f"{{{self.namespace}}}DataRilevazione")
        ET.SubElement(data_rilevazione, f"{{{self.namespace}}}Da").text = data_da
        ET.SubElement(data_rilevazione, f"{{{self.namespace}}}A").text = data_a
        
        elenco_piva = ET.SubElement(corrispettivi, f"{{{self.namespace}}}ElencoPiva")
        ET.SubElement(elenco_piva, f"{{{self.namespace}}}Piva").text = piva
        
        ET.SubElement(corrispettivi, f"{{{self.namespace}}}TipoCorrispettivo").text = tipo_corrispettivo
        
        return self._prettify(root)
    
    def create_ricevute(self, piva: str, data_da: str, data_a: str, flusso: str, ruolo: str) -> str:
        """Crea XML per richiesta ricevute"""
        root = self._create_root()
        tipo_richiesta = ET.SubElement(root, f"{{{self.namespace}}}TipoRichiesta")
        ricevute = ET.SubElement(tipo_richiesta, f"{{{self.namespace}}}Ricevute")
        
        ET.SubElement(ricevute, f"{{{self.namespace}}}Richiesta").text = "RICE"
        
        data_ricezione = ET.SubElement(ricevute, f"{{{self.namespace}}}DataRicezione")
        ET.SubElement(data_ricezione, f"{{{self.namespace}}}Da").text = data_da
        ET.SubElement(data_ricezione, f"{{{self.namespace}}}A").text = data_a
        
        elenco_piva = ET.SubElement(ricevute, f"{{{self.namespace}}}ElencoPiva")
        ET.SubElement(elenco_piva, f"{{{self.namespace}}}Piva").text = piva
        
        ET.SubElement(ricevute, f"{{{self.namespace}}}Flusso").text = flusso
        ET.SubElement(ricevute, f"{{{self.namespace}}}Ruolo").text = ruolo
        ET.SubElement(ricevute, f"{{{self.namespace}}}TipoRicerca").text = "PUNTUALE"
        
        return self._prettify(root)
    
    def _create_root(self) -> ET.Element:
        """Crea l'elemento root con namespace"""
        root = ET.Element(
            f"{{{self.namespace}}}InputMassivo",
            attrib={
                "{http://www.w3.org/2001/XMLSchema-instance}schemaLocation": 
                "http://www.sogei.it/InputPubblico untitled.xsd"
            }
        )
        return root
    
    def _prettify(self, elem) -> str:
        """Formatta l'XML in modo leggibile"""
        rough_string = ET.tostring(elem, encoding='unicode')
        reparsed = minidom.parseString(rough_string)
        return reparsed.toprettyxml(indent="  ")

# ============================================================================
# MODULO: Gestore Richieste
# ============================================================================

class RequestManager:
    """Gestisce l'invio e il monitoraggio delle richieste"""
    
    def __init__(self, session: ADESession, xml_builder: XMLRequestBuilder, logger: Logger):
        self.session = session
        self.xml_builder = xml_builder
        self.logger = logger
        self.requests_sent = []  # Traccia le richieste inviate
    
    def save_xml_request(self, xml_content: str, client_name: str, tipo: str, periodo: str) -> str:
        """Salva la richiesta XML su file per archivio"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"xml_requests/{client_name}_{tipo}_{periodo}_{timestamp}.xml"
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(xml_content)
        
        return filename
    
    def send_request(self, xml_content: str, tipo_richiesta: str, client_data: dict) -> Optional[str]:
        """Invia una richiesta XML all'ADE"""
        try:
            # Prepara headers per l'upload
            headers = {
                'Host': 'ivaservizi.agenziaentrate.gov.it',
                'Cache-Control': 'max-age=0',
                'Accept': 'application/json, text/plain, */*',
                'Accept-Encoding': 'gzip, deflate',
                'Accept-Language': 'it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7',
                'Origin': 'https://ivaservizi.agenziaentrate.gov.it',
                'Content-Type': 'application/xml;charset=utf-8',
                'x-b2bcookie': self.session.xb2bcookie,
                'x-token': self.session.xtoken,
                'x-frame-options': 'deny',
                'X-XSS-Protection': '1; mode=block',
                'Strict-Transport-Security': 'max-age=16070400; includeSubDomains',
                'X-Content-Type-Options': 'nosniff',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            # Determina il tipo per l'URL
            url_tipo = self._get_url_tipo(tipo_richiesta)
            
            # Invia la richiesta
            url = f'https://ivaservizi.agenziaentrate.gov.it/cons/mass-services/rs/file/upload?tipoRichiesta={url_tipo}'
            
            self.logger.log(f"Invio richiesta {tipo_richiesta}...", indent=2)
            
            response = self.session.session.post(
                url,
                headers=headers,
                data=xml_content.encode('utf-8')
            )
            
            if response.status_code == 200:
                request_id = response.text.strip()
                self.logger.log(f"ID: {request_id}", "SUCCESS", indent=3)
                
                # Salva info richiesta
                request_info = {
                    'id': request_id,
                    'tipo': tipo_richiesta,
                    'cliente': client_data['nome_azienda'],
                    'piva': client_data['partita_iva_diretta'],
                    'timestamp': datetime.now().isoformat(),
                    'status': 'INVIATA'
                }
                self.requests_sent.append(request_info)
                self._save_request_tracking(request_info)
                
                return request_id
            else:
                self.logger.log(f"Errore: Status Code {response.status_code}", "ERROR", indent=3)
                return None
                
        except Exception as e:
            self.logger.log(f"Errore invio: {str(e)}", "ERROR", indent=3)
            return None
    
    def _get_url_tipo(self, tipo_richiesta: str) -> str:
        """Determina il parametro tipo per l'URL"""
        if 'CORR' in tipo_richiesta or 'corrispettivi' in tipo_richiesta.lower():
            return 'CORR'
        elif 'RICE' in tipo_richiesta or 'ricevute' in tipo_richiesta.lower():
            return 'RICE'
        else:
            return 'FATT'
    
    def _save_request_tracking(self, request_info: dict):
        """Salva il tracking delle richieste in un file JSON"""
        tracking_file = 'requests_tracking.json'
        
        # Carica tracking esistente
        if os.path.exists(tracking_file):
            with open(tracking_file, 'r', encoding='utf-8') as f:
                tracking = json.load(f)
        else:
            tracking = []
        
        tracking.append(request_info)
        
        with open(tracking_file, 'w', encoding='utf-8') as f:
            json.dump(tracking, f, indent=2, ensure_ascii=False)
    
    def get_request_details(self, request_id: str) -> dict:
        """Recupera i dettagli completi di una richiesta inclusi i file disponibili"""
        try:
            url = f'https://ivaservizi.agenziaentrate.gov.it/cons/mass-services/rs/consultazione/richiesta/{request_id}?v={self.session.unix_time()}'
            
            headers = {
                'Accept': 'application/json, text/plain, */*',
                'x-b2bcookie': self.session.xb2bcookie,
                'x-token': self.session.xtoken
            }
            
            response = self.session.session.get(url, headers=headers)
            
            if response.status_code == 200:
                return response.json()
            else:
                return None
                
        except Exception as e:
            self.logger.log(f"Errore recupero dettagli: {str(e)}", "ERROR", indent=2)
            return None
    
    def check_request_status(self, request_id: str) -> dict:
        """Controlla lo stato di una richiesta"""
        try:
            details = self.get_request_details(request_id)
            
            if details:
                # Estrai dati generali
                dati_generali = details.get('datiGenerali', {})
                stato = dati_generali.get('stato', 'UNKNOWN')
                
                # Verifica se è pronta basandosi sulla presenza di file
                file_prodotto = details.get('fileProdotto', [])
                is_ready = (stato == 'Elaborata' and len(file_prodotto) > 0)
                
                return {
                    'id': request_id,
                    'status': stato,
                    'ready': is_ready,
                    'files_available': len(file_prodotto),
                    'data': details
                }
            else:
                return {'id': request_id, 'status': 'ERROR', 'ready': False, 'files_available': 0}
                
        except Exception as e:
            self.logger.log(f"Errore controllo stato: {str(e)}", "ERROR", indent=2)
            return {'id': request_id, 'status': 'ERROR', 'ready': False, 'files_available': 0}
    
    def get_all_requests_from_ade(self) -> List[dict]:
        """Recupera l'elenco di TUTTE le richieste del cliente corrente dall'ADE"""
        try:
            api_url = f'https://ivaservizi.agenziaentrate.gov.it/cons/mass-services/rs/consultazione/richieste?v={self.session.unix_time()}'
            
            headers = {
                'Accept': 'application/json, text/plain, */*',
                'x-b2bcookie': self.session.xb2bcookie,
                'x-token': self.session.xtoken,
                'Referer': 'https://ivaservizi.agenziaentrate.gov.it/cons/mass-web/',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            self.logger.log("Recupero richieste del cliente...", indent=2)
            response = self.session.session.get(api_url, headers=headers)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    
                    # L'ADE restituisce le richieste nel campo 'richiesteMassive'
                    if isinstance(data, dict) and 'richiesteMassive' in data:
                        requests_list = data['richiesteMassive']
                    elif isinstance(data, list):
                        requests_list = data
                    else:
                        requests_list = []
                    
                    # Ordina per data più recente
                    if requests_list and isinstance(requests_list[0], dict):
                        requests_list.sort(
                            key=lambda x: x.get('dataInserimento', ''), 
                            reverse=True
                        )
                    
                    return self._normalize_list(requests_list)
                except json.JSONDecodeError:
                    return []
            else:
                self.logger.log(f"Status {response.status_code}", "WARNING", indent=2)
                return []
                
        except Exception as e:
            self.logger.log(f"Errore recupero: {str(e)}", "ERROR", indent=2)
            return []
    
    def _is_ready_state(self, data: dict) -> bool:
        """Determina se una richiesta è pronta per il download"""
        # Per l'ADE, solo lo stato "Elaborata" con file disponibili significa pronto
        stato = data.get('stato', '').upper()
        
        if stato == 'ELABORATA':
            # Verifica anche la presenza di file
            return True
        elif 'ELABORAZIONE' in stato or 'ACQUISITA' in stato:
            return False
        
        return False
    
    def _normalize_item(self, raw: dict) -> dict:
        """Normalizza un item della lista richieste"""
        rid = raw.get('idRichiesta', '')
        tipo = raw.get('tipoRichiesta', '')
        data_invio = raw.get('dataInserimento', '')
        stato = raw.get('stato', 'UNKNOWN')
        
        # Determina se è pronta basandosi sullo stato
        ready = False
        if stato == 'Elaborata':
            ready = True
        elif 'elaborazione' in stato.lower():
            ready = False
        
        return {
            'id': rid,
            'tipoRichiesta': tipo,
            'dataInvio': data_invio,
            'stato': stato,
            'ready': ready,
            '_raw': raw
        }
    
    def _normalize_list(self, items: list) -> list:
        """Normalizza una lista di richieste"""
        norm = [self._normalize_item(x) for x in items if isinstance(x, dict)]
        norm.sort(key=lambda x: x.get('dataInvio') or '', reverse=True)
        return norm

# ============================================================================
# MODULO: Gestore Download - CORRETTO
# ============================================================================

class DownloadManager:
    """Gestisce il download e l'organizzazione dei file"""
    
    def __init__(self, session: ADESession, logger: Logger):
        self.session = session
        self.logger = logger
    
    def download_request(self, request_id: str, client_data: dict, tipo: str) -> bool:
        """Scarica i file di una richiesta completata"""
        try:
            self.logger.log(f"Download richiesta {request_id[:20]}...", indent=2)
            
            # Step 1: Recupera i dettagli della richiesta
            url = f'https://ivaservizi.agenziaentrate.gov.it/cons/mass-services/rs/consultazione/richiesta/{request_id}?v={self.session.unix_time()}'
            
            headers = {
                'Accept': 'application/json, text/plain, */*',
                'x-b2bcookie': self.session.xb2bcookie,
                'x-token': self.session.xtoken
            }
            
            response = self.session.session.get(url, headers=headers)
            
            if response.status_code != 200:
                self.logger.log(f"Impossibile recuperare dettagli: Status {response.status_code}", "ERROR", indent=3)
                return False
            
            details = response.json()
            
            # Verifica lo stato
            dati_generali = details.get('datiGenerali', {})
            stato = dati_generali.get('stato', '')
            
            if stato != 'Elaborata':
                self.logger.log(f"Richiesta non pronta. Stato: {stato}", "WARNING", indent=3)
                return False
            
            # Verifica presenza file
            file_prodotto = details.get('fileProdotto', [])
            
            if not file_prodotto:
                self.logger.log("Nessun file disponibile per il download", "WARNING", indent=3)
                return False
            
            downloaded_files = []
            
            # Step 2: Scarica ogni file disponibile
            for i, file_info in enumerate(file_prodotto, 1):
                # Il nome del file nel JSON è "fileProdotto1", "fileProdotto2", etc.
                # Ma nel campo 'file' potrebbe essere memorizzato come "fileProdotto1"
                file_name = file_info.get('file', f'fileProdotto{i}')
                file_size = file_info.get('size', 'N/A')
                elementi = file_info.get('numeroElementiContenuti', 'N/A')
                
                self.logger.log(f"Download {file_name} ({file_size} bytes, {elementi} elementi)...", indent=3)
                
                # URL corretto per il download - usa solo /file/download/ che è quello che funziona
                download_url = f'https://ivaservizi.agenziaentrate.gov.it/cons/mass-services/rs/file/download/id/{request_id}/nomeFile/{file_name}/?v={self.session.unix_time()}'
                
                download_headers = {
                    'Accept': 'application/zip, application/octet-stream, */*',
                    'x-b2bcookie': self.session.xb2bcookie,
                    'x-token': self.session.xtoken,
                    'Referer': 'https://ivaservizi.agenziaentrate.gov.it/cons/mass-web/',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
                
                try:
                    self.logger.log(f"Tentativo download da: {download_url[:80]}...", indent=4)
                    
                    download_response = self.session.session.get(
                        download_url, 
                        headers=download_headers, 
                        stream=True,
                        verify=False
                    )
                    
                    if download_response.status_code == 200:
                        # Determina il nome del file dal Content-Disposition header se disponibile
                        content_disp = download_response.headers.get('Content-Disposition', '')
                        if 'filename=' in content_disp:
                            filename_from_header = content_disp.split('filename=')[-1].strip('"')
                            filename = f"downloads/{client_data['nome_azienda']}_{filename_from_header}"
                        else:
                            filename = f"downloads/{client_data['nome_azienda']}_{request_id}_{file_name}.zip"
                        
                        # Assicurati che la directory downloads esista
                        Path('downloads').mkdir(exist_ok=True)
                        
                        # Salva il file
                        total_size = 0
                        with open(filename, 'wb') as f:
                            for chunk in download_response.iter_content(chunk_size=8192):
                                if chunk:
                                    f.write(chunk)
                                    total_size += len(chunk)
                        
                        self.logger.log(f"✅ Salvato: {filename} ({total_size} bytes)", "SUCCESS", indent=4)
                        downloaded_files.append(filename)
                    else:
                        self.logger.log(f"Errore HTTP {download_response.status_code}", "ERROR", indent=4)
                        # Log del contenuto della risposta per debug
                        if download_response.status_code == 404:
                            self.logger.log("File non trovato - verificare il nome del file", "ERROR", indent=5)
                        
                except Exception as e:
                    self.logger.log(f"Errore download: {str(e)}", "ERROR", indent=4)
            
            # Step 3: Estrai e organizza i file scaricati
            if downloaded_files:
                for zip_file in downloaded_files:
                    try:
                        self._extract_and_organize(zip_file, client_data, tipo)
                    except Exception as e:
                        self.logger.log(f"Errore estrazione {zip_file}: {str(e)}", "WARNING", indent=4)
                
                self.logger.log(f"Download completato: {len(downloaded_files)} file", "SUCCESS", indent=3)
                return True
            else:
                self.logger.log("Nessun file scaricato con successo", "ERROR", indent=3)
                return False
                
        except Exception as e:
            self.logger.log(f"Errore download: {str(e)}", "ERROR", indent=3)
            import traceback
            self.logger.log(f"Traceback: {traceback.format_exc()}", "ERROR", indent=4)
            return False
    
    def _extract_and_organize(self, zip_path: str, client_data: dict, tipo: str):
        """Estrae e organizza i file scaricati"""
        try:
            # Crea struttura directory
            base_dir = f"aziende_processate/{client_data['nome_azienda']}_{client_data['partita_iva_diretta']}_{client_data['codice_fiscale']}"
            tipo_dir = f"{base_dir}/{tipo}_{datetime.now().strftime('%Y%m')}"
            Path(tipo_dir).mkdir(parents=True, exist_ok=True)
            
            # Estrai ZIP
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(tipo_dir)
            
            self.logger.log(f"Estratto in: {tipo_dir}", indent=3)
            
            # Sposta ZIP in archivio
            archive_dir = f"{base_dir}/archive"
            Path(archive_dir).mkdir(parents=True, exist_ok=True)
            shutil.move(zip_path, f"{archive_dir}/{os.path.basename(zip_path)}")
            
        except Exception as e:
            self.logger.log(f"Errore estrazione: {str(e)}", "ERROR", indent=3)

# ============================================================================
# MODULO: Gestore Operazioni Massive
# ============================================================================

class MassiveOperationsManager:
    """Gestisce operazioni su tutti i clienti"""
    
    def __init__(self, session: ADESession, request_manager: RequestManager, 
                 download_manager: DownloadManager, config: Config, logger: Logger):
        self.session = session
        self.request_manager = request_manager
        self.download_manager = download_manager
        self.config = config
        self.logger = logger
    
    def monitor_all_clients_requests(self, filter_type: Optional[str] = None) -> Dict:
        """Monitora le richieste di TUTTI i clienti"""
        all_results = {}
        clients = self.config.get_active_clients()
        
        print("\n" + "="*60)
        print("MONITORAGGIO GLOBALE RICHIESTE")
        print("="*60)
        
        for client_key, client_data in clients.items():
            self.logger.log(f"\n📊 Cliente: {client_data['nome_azienda']}", indent=0)
            
            if not self.session.select_client(client_data):
                print("\n❌ Impossibile selezionare il cliente")
                continue
            
            requests = self.request_manager.get_all_requests_from_ade()
            
            # Conta correttamente le richieste
            elaborated_count = 0
            in_progress_count = 0
            
            for req in requests:
                stato = req.get('stato', '')
                if stato == 'Elaborata':
                    elaborated_count += 1
                elif 'elaborazione' in stato.lower():
                    in_progress_count += 1
            
            total = len(requests)
            print(f"   Totali: {total} | Elaborate: {elaborated_count} | In corso: {in_progress_count}")
            
            if not requests:
                print("   (nessuna richiesta)")
                continue
            
            # Mostra dettagli richieste
            show = min(10, total)
            for req in requests[:show]:
                rid = req.get('id', 'N/A')
                stato = req.get('stato', 'N/D')
                tipo = req.get('tipoRichiesta', '')
                data = req.get('dataInvio', '')
                
                # Icona basata sullo stato
                if stato == 'Elaborata':
                    icon = '✅'
                elif 'elaborazione' in stato.lower():
                    icon = '⏳'
                else:
                    icon = '❓'
                
                print(f"   {icon} {rid[:28]}... | {stato} | {tipo}")
                if data:
                    print(f"      Data: {data}")
                print("   " + "─"*40)
            
            all_results[client_key] = {
                'total': total,
                'ready': elaborated_count,
                'in_progress': in_progress_count
            }
        
        return all_results
    
    def download_all_ready_requests(self, filter_type: Optional[str] = None) -> Dict:
        """Scarica tutte le richieste pronte di tutti i clienti"""
        results = {}
        clients = self.config.get_active_clients()
        
        print("\n" + "="*60)
        print("DOWNLOAD MASSIVO RICHIESTE PRONTE")
        print("="*60)
        
        for client_key, client_data in clients.items():
            self.logger.log(f"\n📥 Cliente: {client_data['nome_azienda']}", indent=0)
            
            # Seleziona il cliente
            if not self.session.select_client(client_data):
                self.logger.log("Impossibile selezionare", "ERROR", indent=1)
                continue
            
            # Recupera richieste
            requests = self.request_manager.get_all_requests_from_ade()
            
            # Filtra solo quelle con stato "Elaborata"
            ready_requests = [r for r in requests if r.get('stato') == 'Elaborata']
            
            # Filtra per tipo se richiesto
            if filter_type:
                if filter_type == 'CORRISPETTIVI':
                    ready_requests = [r for r in ready_requests if 'CORR' in r.get('tipoRichiesta', '')]
                elif filter_type == 'FATTURE':
                    ready_requests = [r for r in ready_requests if 'FATT' in r.get('tipoRichiesta', '')]
            
            if ready_requests:
                self.logger.log(f"Trovate {len(ready_requests)} richieste pronte", indent=1)
                
                downloaded = 0
                failed = 0
                
                for req in ready_requests:
                    req_id = req.get('id', '')
                    tipo = req.get('tipoRichiesta', 'UNKNOWN')
                    
                    # Verifica prima se ci sono file disponibili
                    details = self.request_manager.get_request_details(req_id)
                    if details and details.get('fileProdotto'):
                        if self.download_manager.download_request(req_id, client_data, tipo):
                            downloaded += 1
                        else:
                            failed += 1
                    else:
                        self.logger.log(f"Nessun file per {req_id}", "WARNING", indent=2)
                    
                    time.sleep(0.5)  # Pausa tra download
                
                results[client_key] = {
                    'cliente': client_data['nome_azienda'],
                    'downloaded': downloaded,
                    'failed': failed
                }
                
                self.logger.log(f"Download completati: {downloaded}", "SUCCESS", indent=1)
                if failed > 0:
                    self.logger.log(f"Download falliti: {failed}", "ERROR", indent=1)
            else:
                self.logger.log("Nessuna richiesta pronta", indent=1)
                results[client_key] = {
                    'cliente': client_data['nome_azienda'],
                    'downloaded': 0,
                    'failed': 0
                }
            
            time.sleep(1)  # Pausa tra clienti
        
        # Riepilogo
        print("\n" + "="*60)
        print("RIEPILOGO DOWNLOAD")
        print("="*60)
        
        totale_download = sum(r['downloaded'] for r in results.values())
        totale_errori = sum(r['failed'] for r in results.values())
        
        print(f"\n✅ Totale download completati: {totale_download}")
        if totale_errori > 0:
            print(f"❌ Totale download falliti: {totale_errori}")
        
        return results

# ============================================================================
# MODULO: Interfaccia CLI
# ============================================================================

class CLInterface:
    """Interfaccia a riga di comando interattiva"""
    
    def __init__(self):
        self.config = Config()
        self.logger = Logger()
        self.session = ADESession(self.config, self.logger)
        self.xml_builder = XMLRequestBuilder(self.logger)
        self.request_manager = RequestManager(self.session, self.xml_builder, self.logger)
        self.download_manager = DownloadManager(self.session, self.logger)
        self.massive_ops = MassiveOperationsManager(
            self.session, self.request_manager, self.download_manager, 
            self.config, self.logger
        )
        self.selected_clients = []
        self.selected_services = []
        self.period = {'start': None, 'end': None}
    
    def run(self):
        """Avvia l'interfaccia"""
        self.show_header()
        
        if not self.session.login():
            print("\n❌ Impossibile effettuare il login. Verificare le credenziali.")
            return
        
        while True:
            choice = self.show_main_menu()
            
            if choice == '1':
                self.wizard_new_request()
            elif choice == '2':
                self.monitor_requests_menu()
            elif choice == '3':
                self.download_menu()
            elif choice == '4':
                self.show_configuration()
            elif choice == '5':
                print("\n👋 Arrivederci!")
                self.session.logout()
                break
            else:
                print("\n⚠️  Scelta non valida")
    
    def show_header(self):
        """Mostra l'header dell'applicazione"""
        print("\n" + "="*60)
        print("╔" + " SISTEMA INVII MASSIVI - AGENZIA ENTRATE ".center(58) + "╗")
        print("╔" + " Versione 3.2.0 - FIXED ".center(58) + "╗")
        print("="*60)
    
    def show_main_menu(self) -> str:
        """Mostra il menu principale"""
        print("\n" + "─"*40)
        print("MENU PRINCIPALE")
        print("─"*40)
        print("[1] 📤 Nuova Richiesta Massiva (Wizard)")
        print("[2] 📊 Monitoraggio Richieste")
        print("[3] 📥 Download Richieste")
        print("[4] ⚙️  Configurazione")
        print("[5] 🚪 Esci")
        print("─"*40)
        
        return input("\n▶ Seleziona operazione: ")
    
    def monitor_requests_menu(self):
        """Menu monitoraggio richieste"""
        print("\n" + "="*60)
        print("MONITORAGGIO RICHIESTE")
        print("="*60)
        
        print("\n[1] 🌐 Monitora TUTTI i clienti")
        print("[2] 💰 Monitora solo CORRISPETTIVI (tutti i clienti)")
        print("[3] 📄 Monitora solo FATTURE (tutti i clienti)")
        print("[4] 👤 Monitora singolo cliente")
        print("[5] 🔍 Cerca richiesta per ID")
        
        choice = input("\n▶ Seleziona opzione: ")
        
        if choice == '1':
            self.massive_ops.monitor_all_clients_requests()
        elif choice == '2':
            self.massive_ops.monitor_all_clients_requests(filter_type='CORRISPETTIVI')
        elif choice == '3':
            self.massive_ops.monitor_all_clients_requests(filter_type='FATTURE')
        elif choice == '4':
            self.monitor_single_client()
        elif choice == '5':
            self.search_request_by_id()
        
        input("\n▶ Premi INVIO per continuare...")
    
    def download_menu(self):
        """Menu download"""
        print("\n" + "="*60)
        print("DOWNLOAD RICHIESTE")
        print("="*60)
        
        print("\n[1] 📥 Download TUTTE le richieste pronte (tutti i clienti)")
        print("[2] 💰 Download solo CORRISPETTIVI pronti")
        print("[3] 📄 Download solo FATTURE pronte")
        print("[4] 👤 Download per singolo cliente")
        print("[5] 🔍 Download per ID richiesta")
        
        choice = input("\n▶ Seleziona opzione: ")
        
        if choice == '1':
            self.massive_ops.download_all_ready_requests()
        elif choice == '2':
            self.massive_ops.download_all_ready_requests(filter_type='CORRISPETTIVI')
        elif choice == '3':
            self.massive_ops.download_all_ready_requests(filter_type='FATTURE')
        elif choice == '4':
            self.download_single_client()
        elif choice == '5':
            self.download_by_id()
        
        input("\n▶ Premi INVIO per continuare...")
    
    def monitor_single_client(self):
        """Monitora richieste di un singolo cliente"""
        clients = self.config.get_active_clients()
        print("\nSelezione cliente:")
        for i, (key, client) in enumerate(clients.items(), 1):
            print(f"[{i}] {client['nome_azienda']} (P.IVA: {client['partita_iva_diretta']})")
        
        try:
            choice = int(input("\n▶ Seleziona cliente: ")) - 1
            client_list = list(clients.values())
            
            if 0 <= choice < len(client_list):
                client = client_list[choice]
                
                if self.session.select_client(client):
                    requests = self.request_manager.get_all_requests_from_ade()
                    
                    if requests:
                        print(f"\n📊 Richieste per {client['nome_azienda']}: {len(requests)}")
                        print("─"*60)
                        
                        for req in requests:
                            req_id = req.get('id', 'N/A')
                            tipo = req.get('tipoRichiesta', 'N/A')
                            stato = req.get('stato', 'N/D')
                            data = req.get('dataInvio', 'N/A')
                            
                            # Icona basata sullo stato
                            if stato == 'Elaborata':
                                icon = '✅'
                                # Verifica se ci sono file
                                details = self.request_manager.get_request_details(req_id)
                                if details:
                                    file_count = len(details.get('fileProdotto', []))
                                    if file_count > 0:
                                        stato += f" ({file_count} file)"
                            elif 'elaborazione' in stato.lower():
                                icon = '⏳'
                            else:
                                icon = '❓'
                            
                            print(f"{icon} {req_id[:30]}...")
                            print(f"   Tipo: {tipo} | Stato: {stato}")
                            print(f"   Data: {data}")
                            print("─"*40)
                    else:
                        print("\n⚠️  Nessuna richiesta trovata")
                else:
                    print("\n❌ Impossibile selezionare il cliente")
            else:
                print("\n⚠️  Selezione non valida")
        except (ValueError, IndexError):
            print("\n⚠️  Selezione non valida")
    
    def search_request_by_id(self):
        """Cerca una richiesta per ID"""
        request_id = input("\n▶ Inserisci l'ID della richiesta: ").strip()
        
        if not request_id:
            print("\n⚠️  ID non valido")
            return
        
        # Usa il primo cliente per autenticazione
        clients = self.config.get_active_clients()
        if clients:
            first_client = list(clients.values())[0]
            
            if self.session.select_client(first_client):
                status = self.request_manager.check_request_status(request_id)
                
                if status['status'] != 'ERROR':
                    print("\n" + "="*50)
                    print(f"📋 Richiesta: {request_id}")
                    print(f"   Stato: {status['status']}")
                    print(f"   Pronta: {'✅ SI' if status['ready'] else '⏳ NO'}")
                    print(f"   File disponibili: {status['files_available']}")
                    
                    if status.get('data'):
                        data = status['data']
                        dati_generali = data.get('datiGenerali', {})
                        
                        for key, value in dati_generali.items():
                            if key not in ['idRichiesta', 'stato']:
                                print(f"   {key}: {value}")
                        
                        # Mostra info sui file se disponibili
                        file_prodotto = data.get('fileProdotto', [])
                        if file_prodotto:
                            print("\n   File disponibili per download:")
                            for file_info in file_prodotto:
                                nome = file_info.get('file', 'N/A')
                                size = file_info.get('size', 'N/A')
                                elementi = file_info.get('numeroElementiContenuti', 'N/A')
                                print(f"     • {nome}: {size} bytes, {elementi} elementi")
                    
                    print("="*50)
                else:
                    print("\n❌ Richiesta non trovata")
            else:
                print("\n❌ Impossibile autenticarsi")
    
    def download_single_client(self):
        """Download richieste di un singolo cliente"""
        clients = self.config.get_active_clients()
        
        print("\nSelezione cliente:")
        for i, (key, client) in enumerate(clients.items(), 1):
            print(f"[{i}] {client['nome_azienda']} (P.IVA: {client['partita_iva_diretta']})")
        
        try:
            choice = int(input("\n▶ Seleziona cliente: ")) - 1
            client_list = list(clients.values())
            
            if 0 <= choice < len(client_list):
                client = client_list[choice]
                
                if self.session.select_client(client):
                    requests = self.request_manager.get_all_requests_from_ade()
                    ready = [r for r in requests if r.get('stato') == 'Elaborata']
                    
                    if ready:
                        print(f"\n✅ Trovate {len(ready)} richieste pronte")
                        
                        # Mostra dettagli
                        for req in ready[:5]:
                            req_id = req.get('id', '')
                            tipo = req.get('tipoRichiesta', '')
                            print(f"  • {req_id[:30]}... ({tipo})")
                        
                        if len(ready) > 5:
                            print(f"  ... e altre {len(ready)-5}")
                        
                        if input("\n▶ Scaricare tutte? (S/N): ").upper() == 'S':
                            downloaded = 0
                            failed = 0
                            
                            for req in ready:
                                req_id = req.get('id', '')
                                tipo = req.get('tipoRichiesta', 'UNKNOWN')
                                
                                if self.download_manager.download_request(req_id, client, tipo):
                                    downloaded += 1
                                else:
                                    failed += 1
                                
                                time.sleep(0.5)
                            
                            print(f"\n✅ Download completati: {downloaded}")
                            if failed > 0:
                                print(f"❌ Download falliti: {failed}")
                    else:
                        print("\n⚠️  Nessuna richiesta pronta")
                else:
                    print("\n❌ Impossibile selezionare il cliente")
        except (ValueError, IndexError):
            print("\n⚠️  Selezione non valida")
    
    def download_by_id(self):
        """Download di una richiesta specifica"""
        request_id = input("\n▶ Inserisci l'ID della richiesta: ").strip()
        
        if not request_id:
            print("\n⚠️  ID non valido")
            return
        
        # Usa il primo cliente per autenticazione
        clients = self.config.get_active_clients()
        if clients:
            first_client = list(clients.values())[0]
            
            if self.session.select_client(first_client):
                # Prima mostra i dettagli
                print("\n📋 Recupero dettagli richiesta...")
                
                url = f'https://ivaservizi.agenziaentrate.gov.it/cons/mass-services/rs/consultazione/richiesta/{request_id}?v={self.session.unix_time()}'
                
                headers = {
                    'Accept': 'application/json, text/plain, */*',
                    'x-b2bcookie': self.session.xb2bcookie,
                    'x-token': self.session.xtoken
                }
                
                response = self.session.session.get(url, headers=headers, verify=False)
                
                if response.status_code == 200:
                    details = response.json()
                    dati_generali = details.get('datiGenerali', {})
                    stato = dati_generali.get('stato', '')
                    file_prodotto = details.get('fileProdotto', [])
                    
                    print(f"\n📊 Stato: {stato}")
                    print(f"📁 File disponibili: {len(file_prodotto)}")
                    
                    if file_prodotto:
                        print("\n📄 Dettaglio file:")
                        for i, file_info in enumerate(file_prodotto, 1):
                            nome = file_info.get('file', f'fileProdotto{i}')
                            size = file_info.get('size', 'N/A')
                            elementi = file_info.get('numeroElementiContenuti', 'N/A')
                            print(f"   • {nome}: {size} bytes, {elementi} elementi")
                    
                    if stato == 'Elaborata' and file_prodotto:
                        print("\n✅ Richiesta pronta per il download")
                        
                        if input("\n▶ Procedere con il download? (S/N): ").upper() == 'S':
                            tipo = dati_generali.get('tipoRichiesta', 'UNKNOWN')
                            
                            # Test download diretto
                            print("\n🔄 Avvio download...")
                            
                            success = self.download_manager.download_request(request_id, first_client, tipo)
                            
                            if success:
                                print("\n✅ Download completato con successo!")
                            else:
                                print("\n❌ Download fallito - verificare i log per dettagli")
                                
                                # Prova download manuale per debug
                                if input("\n▶ Vuoi provare il download manuale per debug? (S/N): ").upper() == 'S':
                                    self._manual_download_debug(request_id, file_prodotto)
                    else:
                        print(f"\n⏳ Richiesta non pronta per il download")
                        if stato == 'Acquisita - in elaborazione':
                            print("   La richiesta è ancora in elaborazione. Riprova più tardi.")
                else:
                    print(f"\n❌ Errore recupero dettagli: HTTP {response.status_code}")
            else:
                print("\n❌ Impossibile autenticarsi")
    
    def _manual_download_debug(self, request_id: str, file_prodotto: list):
        """Test manuale di download per debug"""
        print("\n🔧 DEBUG: Test download manuale")
        
        for i, file_info in enumerate(file_prodotto, 1):
            file_name = file_info.get('file', f'fileProdotto{i}')
            
            # URL esatto come nell'esempio funzionante
            url = f'https://ivaservizi.agenziaentrate.gov.it/cons/mass-services/rs/file/download/id/{request_id}/nomeFile/{file_name}/?v={self.session.unix_time()}'
            
            print(f"\n📎 Tentativo download {file_name}")
            print(f"   URL: {url[:100]}...")
            
            headers = {
                'Accept': 'application/zip, application/octet-stream, */*',
                'x-b2bcookie': self.session.xb2bcookie,
                'x-token': self.session.xtoken,
                'Referer': 'https://ivaservizi.agenziaentrate.gov.it/cons/mass-web/',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            try:
                # Prima prova HEAD per verificare
                head_response = self.session.session.head(url, headers=headers, verify=False)
                print(f"   HEAD Response: {head_response.status_code}")
                
                if head_response.status_code == 200:
                    # Procedi con GET
                    response = self.session.session.get(url, headers=headers, stream=True, verify=False)
                    
                    if response.status_code == 200:
                        filename = f"downloads/debug_{request_id}_{file_name}.zip"
                        Path('downloads').mkdir(exist_ok=True)
                        
                        total_size = 0
                        with open(filename, 'wb') as f:
                            for chunk in response.iter_content(chunk_size=8192):
                                if chunk:
                                    f.write(chunk)
                                    total_size += len(chunk)
                        
                        print(f"   ✅ Download riuscito: {filename} ({total_size} bytes)")
                    else:
                        print(f"   ❌ GET fallito: {response.status_code}")
                        print(f"   Response: {response.text[:200]}")
                else:
                    print(f"   ❌ File non accessibile")
                    
            except Exception as e:
                print(f"   ❌ Errore: {str(e)}")
    
    def wizard_new_request(self):
        """Wizard guidato per nuova richiesta"""
        print("\n" + "="*60)
        print("WIZARD INVIO MASSIVO")
        print("="*60)
        
        # Step 1: Selezione Clienti
        print("\n📋 STEP 1/3: Selezione Clienti")
        print("─"*40)
        self.selected_clients = self.select_clients_wizard()
        
        if not self.selected_clients:
            print("\n⚠️  Nessun cliente selezionato")
            return
        
        # Step 2: Selezione Servizi
        print("\n📋 STEP 2/3: Selezione Servizi")
        print("─"*40)
        self.selected_services = self.select_services_wizard()
        
        if not self.selected_services:
            print("\n⚠️  Nessun servizio selezionato")
            return
        
        # Step 3: Periodo
        print("\n📋 STEP 3/3: Definizione Periodo")
        print("─"*40)
        self.period = self.select_period_wizard()
        
        # Riepilogo
        self.show_summary()
        
        if input("\n▶ Confermi l'invio? (S/N): ").upper() == 'S':
            self.execute_requests()
        else:
            print("\n⚠️  Operazione annullata")
    
    def select_clients_wizard(self) -> List[dict]:
        """Wizard selezione clienti"""
        clients = self.config.get_active_clients()
        selected = []
        
        print("\n[0] 🌐 Tutti i clienti attivi")
        for i, (key, client) in enumerate(clients.items(), 1):
            status = "✔" if client.get('corrispettivi_abilitati', False) else "○"
            print(f"[{i}] {status} {client['nome_azienda']} (P.IVA: {client['partita_iva_diretta']})")
        
        print("\nℹ️  Seleziona i clienti (numeri separati da virgola, 0 per tutti)")
        choice = input("▶ Selezione: ")
        
        if choice == '0':
            selected = list(clients.values())
        else:
            indices = [int(x.strip()) for x in choice.split(',') if x.strip().isdigit()]
            client_list = list(clients.values())
            selected = [client_list[i-1] for i in indices if 0 < i <= len(client_list)]
        
        print(f"\n✅ Selezionati {len(selected)} clienti")
        return selected
    
    def select_services_wizard(self) -> List[str]:
        """Wizard selezione servizi"""
        services = []
        
        print("\nServizi disponibili:")
        print("[1] 📄 Fatture Emesse")
        print("[2] 📄 Fatture Ricevute")
        print("[3] 💰 Corrispettivi (tutti i tipi)")
        print("[4] 🧾 Ricevute")
        print("[5] 🌐 Tutti i servizi")
        
        choice = input("\n▶ Seleziona servizi (numeri separati da virgola): ")
        
        selections = [int(x.strip()) for x in choice.split(',') if x.strip().isdigit()]
        
        if 5 in selections:
            services = ['FATTURE_EMESSE', 'FATTURE_RICEVUTE', 'CORRISPETTIVI', 'RICEVUTE']
        else:
            if 1 in selections: services.append('FATTURE_EMESSE')
            if 2 in selections: services.append('FATTURE_RICEVUTE')
            if 3 in selections: services.append('CORRISPETTIVI')
            if 4 in selections: services.append('RICEVUTE')
        
        print(f"\n✅ Selezionati {len(services)} servizi")
        return services
    
    def select_period_wizard(self) -> dict:
        """Wizard selezione periodo"""
        print("\nDefinizione periodo:")
        print("[1] 📅 Mese corrente")
        print("[2] 📅 Mese precedente")
        print("[3] 📅 Ultimi 30 giorni")
        print("[4] 📅 Periodo personalizzato")
        
        choice = input("\n▶ Seleziona periodo: ")
        
        today = datetime.now()
        
        if choice == '1':
            start = today.replace(day=1)
            end = today
        elif choice == '2':
            first_day_current = today.replace(day=1)
            end = first_day_current - timedelta(days=1)
            start = end.replace(day=1)
        elif choice == '3':
            start = today - timedelta(days=30)
            end = today
        else:
            start_str = input("▶ Data inizio (YYYY-MM-DD): ")
            end_str = input("▶ Data fine (YYYY-MM-DD): ")
            start = datetime.strptime(start_str, '%Y-%m-%d')
            end = datetime.strptime(end_str, '%Y-%m-%d')
        
        period = {
            'start': start.strftime('%Y-%m-%d'),
            'end': end.strftime('%Y-%m-%d')
        }
        
        print(f"\n✅ Periodo: {period['start']} → {period['end']}")
        return period
    
    def show_summary(self):
        """Mostra riepilogo richiesta"""
        print("\n" + "="*60)
        print("RIEPILOGO RICHIESTA")
        print("="*60)
        
        print(f"\n📋 Clienti selezionati: {len(self.selected_clients)}")
        for client in self.selected_clients[:3]:
            print(f"   • {client['nome_azienda']}")
        if len(self.selected_clients) > 3:
            print(f"   ... e altri {len(self.selected_clients)-3}")
        
        print(f"\n🔧 Servizi selezionati:")
        for service in self.selected_services:
            print(f"   • {service}")
        
        print(f"\n📅 Periodo: {self.period['start']} → {self.period['end']}")
        
        total_requests = len(self.selected_clients) * len(self.selected_services)
        if 'CORRISPETTIVI' in self.selected_services:
            # Conta clienti con corrispettivi abilitati
            clients_with_corr = sum(1 for c in self.selected_clients if c.get('corrispettivi_abilitati', False))
            total_requests += clients_with_corr * 4  # 5 tipi - 1 già contato
        
        print(f"\n📊 Totale richieste da inviare: ~{total_requests}")
    
    def execute_requests(self):
        """Esegue l'invio delle richieste"""
        print("\n" + "="*60)
        print("INVIO RICHIESTE IN CORSO")
        print("="*60)
        
        success_count = 0
        error_count = 0
        
        for client in self.selected_clients:
            print(f"\n🏢 Cliente: {client['nome_azienda']}")
            print("─"*40)
            
            # Seleziona il cliente
            if not self.session.select_client(client):
                print(f"❌ Impossibile selezionare il cliente")
                error_count += 1
                continue
            
            for service in self.selected_services:
                if service == 'FATTURE_EMESSE':
                    xml = self.xml_builder.create_fatture_emesse(
                        client['partita_iva_diretta'],
                        self.period['start'],
                        self.period['end']
                    )
                    self._send_and_save(xml, 'FATTURE_EMESSE', client)
                    success_count += 1
                    
                elif service == 'FATTURE_RICEVUTE':
                    xml = self.xml_builder.create_fatture_ricevute(
                        client['partita_iva_diretta'],
                        self.period['start'],
                        self.period['end']
                    )
                    self._send_and_save(xml, 'FATTURE_RICEVUTE', client)
                    success_count += 1
                    
                elif service == 'CORRISPETTIVI':
                    # Invia richiesta per ogni tipo di corrispettivo solo se abilitati
                    if client.get('corrispettivi_abilitati', False):
                        for tipo_corr in XMLRequestBuilder.TIPI_CORRISPETTIVI:
                            xml = self.xml_builder.create_corrispettivi(
                                client['partita_iva_diretta'],
                                self.period['start'],
                                self.period['end'],
                                tipo_corr
                            )
                            self._send_and_save(xml, f'CORRISPETTIVI_{tipo_corr}', client)
                            success_count += 1
                            time.sleep(1)  # Pausa tra richieste
                    else:
                        self.logger.log("Corrispettivi non abilitati per questo cliente", "WARNING", indent=1)
                    
                elif service == 'RICEVUTE':
                    xml = self.xml_builder.create_ricevute(
                        client['partita_iva_diretta'],
                        self.period['start'],
                        self.period['end'],
                        'ALL',
                        'CESSIONARIO'
                    )
                    self._send_and_save(xml, 'RICEVUTE', client)
                    success_count += 1
                
                time.sleep(0.5)  # Pausa tra servizi
        
        print("\n" + "="*60)
        print(f"✅ Richieste inviate con successo: {success_count}")
        if error_count > 0:
            print(f"❌ Richieste con errori: {error_count}")
        print("="*60)
        
        input("\n▶ Premi INVIO per continuare...")
    
    def _send_and_save(self, xml_content: str, tipo: str, client: dict):
        """Helper per inviare e salvare richiesta"""
        # Salva XML
        periodo = f"{self.period['start']}_{self.period['end']}"
        xml_file = self.request_manager.save_xml_request(
            xml_content,
            client['nome_azienda'],
            tipo,
            periodo
        )
        
        # Invia richiesta
        request_id = self.request_manager.send_request(xml_content, tipo, client)
        
        if request_id:
            print(f"   ✅ {tipo}: ID {request_id}")
        else:
            print(f"   ❌ {tipo}: Errore invio")
    
    def show_configuration(self):
        """Mostra la configurazione corrente"""
        print("\n" + "="*60)
        print("CONFIGURAZIONE SISTEMA")
        print("="*60)
        
        config = self.config.config
        
        print("\n📋 Credenziali ADE:")
        print(f"   CF: {config['credenziali_ade']['codice_fiscale']}")
        print(f"   CF Studio: {config['credenziali_ade']['codice_fiscale_studio']}")
        
        print("\n🏢 Clienti Configurati:")
        clients = self.config.get_active_clients()
        clients_corr = self.config.get_clients_with_corrispettivi()
        
        print(f"   Totale clienti attivi: {len(clients)}")
        print(f"   Clienti con corrispettivi: {len(clients_corr)}")
        
        print("\n   Dettaglio clienti:")
        for client in list(clients.values())[:5]:
            corr = "✔" if client.get('corrispettivi_abilitati') else "✗"
            active = "✔" if client.get('attivo') else "✗"
            print(f"   • {client['nome_azienda']}")
            print(f"     P.IVA: {client['partita_iva_diretta']} | Attivo: {active} | Corr: {corr}")
        
        if len(clients) > 5:
            print(f"   ... e altri {len(clients)-5} clienti")
        
        print("\n📁 Directory Sistema:")
        print(f"   Downloads: downloads/")
        print(f"   XML Requests: xml_requests/")
        print(f"   Aziende: aziende_processate/")
        print(f"   Logs: logs/")
        
        print("\n📊 Statistiche:")
        # Conta richieste salvate
        tracking_file = 'requests_tracking.json'
        if os.path.exists(tracking_file):
            with open(tracking_file, 'r') as f:
                requests = json.load(f)
                print(f"   Richieste tracciate: {len(requests)}")
                
                # Conta per tipo
                types_count = {}
                for req in requests:
                    tipo = req.get('tipo', 'UNKNOWN')
                    types_count[tipo] = types_count.get(tipo, 0) + 1
                
                for tipo, count in types_count.items():
                    print(f"     - {tipo}: {count}")
        
        input("\n▶ Premi INVIO per continuare...")

# ============================================================================
# MAIN
# ============================================================================

def main():
    """Funzione principale"""
    try:
        cli = CLInterface()
        cli.run()
    except KeyboardInterrupt:
        print("\n\n⚠️  Operazione interrotta dall'utente")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Errore critico: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()