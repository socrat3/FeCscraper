## Script per il download dei corrispettivi telematici dall'Agenzia delle Entrate
## Integrazione con sistema BioFatture Gemini
## Versione 3.1 - Compatibile con config_ade_system.json esistente

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import re
import time
from datetime import datetime, timedelta
import sys
import pytz
import json
import os
from pathlib import Path
import logging
from typing import Optional, Dict, Any, Tuple

class CorrispettiviDownloader:
    """Classe per gestire il download dei corrispettivi telematici"""
    
    def __init__(self, config_path: str = 'config_ade_system.json'):
        """Inizializza il downloader con la configurazione"""
        self.config_path = config_path
        self.config = self.carica_configurazione()
        self.session = None
        self.setup_logging()
        
    def carica_configurazione(self) -> Dict[str, Any]:
        """Carica la configurazione dal file JSON"""
        if not os.path.exists(self.config_path):
            raise FileNotFoundError(f"File di configurazione {self.config_path} non trovato")
        
        with open(self.config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def setup_logging(self):
        """Configura il sistema di logging"""
        log_config = self.config.get('logging', {})
        log_level = getattr(logging, log_config.get('livello', 'INFO'))
        
        # Crea directory logs se non esiste
        log_dir = self.config.get('directory_sistema', {}).get('logs', 'logs_sistema')
        Path(log_dir).mkdir(parents=True, exist_ok=True)
        
        # Configurazione logger
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        
        handlers = []
        
        # Console handler
        if log_config.get('console_log', True):
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(logging.Formatter(log_format))
            handlers.append(console_handler)
        
        # File handler
        if log_config.get('file_log', True):
            file_handler = logging.FileHandler(
                f"{log_dir}/corrispettivi_{datetime.now().strftime('%Y%m%d')}.log",
                encoding='utf-8'
            )
            file_handler.setFormatter(logging.Formatter(log_format))
            handlers.append(file_handler)
        
        logging.basicConfig(level=log_level, handlers=handlers)
        self.logger = logging.getLogger('CorrispettiviDownloader')
    
    @staticmethod
    def unix_time() -> str:
        """Genera timestamp Unix in millisecondi"""
        dt = datetime.now(tz=pytz.utc)
        return str(int(dt.timestamp() * 1000))
    
    @staticmethod
    def formatta_importo(importo_str: str) -> str:
        """Converte l'importo dal formato +000000000015,00 a formato leggibile"""
        try:
            importo_clean = importo_str.replace('+', '').lstrip('0')
            if not importo_clean:
                return "0,00"
            return importo_clean
        except:
            return importo_str
    
    def crea_sessione(self) -> requests.Session:
        """Crea una nuova sessione HTTP"""
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Connection': 'keep-alive'
        })
        return session
    
    def login_agenzia_entrate(self, session: requests.Session) -> str:
        """Effettua il login al portale dell'Agenzia delle Entrate"""
        cred = self.config['credenziali_ade']
        
        self.logger.info('Collegamento alla homepage...')
        
        # Setup cookies iniziali
        cookie_obj1 = requests.cookies.create_cookie(
            domain='ivaservizi.agenziaentrate.gov.it',
            name='LFR_SESSION_STATE_20159',
            value='expired'
        )
        session.cookies.set_cookie(cookie_obj1)
        
        cookie_obj2 = requests.cookies.create_cookie(
            domain='ivaservizi.agenziaentrate.gov.it',
            name='LFR_SESSION_STATE_10811916',
            value=self.unix_time()
        )
        session.cookies.set_cookie(cookie_obj2)
        
        # Homepage
        r = session.get('https://ivaservizi.agenziaentrate.gov.it/portale/web/guest', 
                       verify=self.config.get('sicurezza', {}).get('verifica_certificati', True))
        
        self.logger.info('Effettuo il login...')
        payload = {
            '_58_saveLastPath': 'false',
            '_58_redirect': '',
            '_58_doActionAfterLogin': 'false',
            '_58_login': cred['codice_fiscale'],
            '_58_pin': cred['pin'],
            '_58_password': cred['password']
        }
        
        r = session.post(
            'https://ivaservizi.agenziaentrate.gov.it/portale/home?p_p_id=58&p_p_lifecycle=1&p_p_state=normal&p_p_mode=view&p_p_col_id=column-1&p_p_col_pos=3&p_p_col_count=4&_58_struts_action=%2Flogin%2Flogin',
            data=payload
        )
        
        # Estrai p_auth token
        liferay_match = re.findall(r"Liferay.authToken = '.*';", r.text)
        if not liferay_match:
            raise ValueError("Token di autenticazione non trovato")
        
        p_auth = liferay_match[0].replace("Liferay.authToken = '", "").replace("';", "")
        
        # API call
        r = session.get('https://ivaservizi.agenziaentrate.gov.it/dp/api?v=' + self.unix_time())
        
        return p_auth
    
    def seleziona_utenza(self, session: requests.Session, p_auth: str, cliente: Dict[str, Any]) -> bool:
        """Seleziona il tipo di incarico/utenza per il cliente"""
        try:
            profilo = cliente.get('profilo_accesso', 1)
            cf_studio = self.config['credenziali_ade']['codice_fiscale_studio'].strip()
            cf_cliente = cliente['codice_fiscale'].strip()
            piva_cliente = cliente['partita_iva_diretta'].strip()
            
            self.logger.info(f'Seleziono utenza per {cliente["nome_azienda"]} (profilo {profilo})')
            
            if profilo == 1:  # Delega Diretta
                payload = {'cf_inserito': cf_cliente}
                r = session.post(
                    f'https://ivaservizi.agenziaentrate.gov.it/portale/scelta-utenza-lavoro?p_auth={p_auth}&p_p_id=SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet&p_p_lifecycle=1&p_p_state=normal&p_p_mode=view&p_p_col_id=column-1&p_p_col_count=1&_SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet_javax.portlet.action=delegaDirettaAction',
                    data=payload
                )
                
                payload = {'cf_inserito': cf_cliente, 'sceltapiva': piva_cliente}
                r = session.post(
                    f'https://ivaservizi.agenziaentrate.gov.it/portale/scelta-utenza-lavoro?p_auth={p_auth}&p_p_id=SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet&p_p_lifecycle=1&p_p_state=normal&p_p_mode=view&p_p_col_id=column-1&p_p_col_count=1&_SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet_javax.portlet.action=delegaDirettaAction',
                    data=payload
                )
                
            elif profilo == 2:  # Me stesso
                payload = {'sceltaincarico': cf_studio + '-000', 'tipoincaricante': 'incDiretto'}
                r = session.post(
                    f'https://ivaservizi.agenziaentrate.gov.it/portale/scelta-utenza-lavoro?p_auth={p_auth}&p_p_id=SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet&p_p_lifecycle=1&p_p_state=normal&p_p_mode=view&p_p_col_id=column-1&p_p_col_count=1&_SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet_javax.portlet.action=meStessoAction',
                    data=payload
                )
                
                payload = {'sceltaincarico': cf_studio + '-000', 'tipoincaricante': 'incDiretto', 'sceltapiva': piva_cliente}
                r = session.post(
                    f'https://ivaservizi.agenziaentrate.gov.it/portale/scelta-utenza-lavoro?p_auth={p_auth}&p_p_id=SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet&p_p_lifecycle=1&p_p_state=normal&p_p_mode=view&p_p_col_id=column-1&p_p_col_count=1&_SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet_javax.portlet.action=meStessoAction',
                    data=payload
                )
                
            else:  # Studio Associato (default)
                payload = {'sceltaincarico': cf_studio + '-000', 'tipoincaricante': 'incDelega', 'cf_inserito': cf_cliente}
                r = session.post(
                    f'https://ivaservizi.agenziaentrate.gov.it/portale/scelta-utenza-lavoro?p_auth={p_auth}&p_p_id=SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet&p_p_lifecycle=1&p_p_state=normal&p_p_mode=view&p_p_col_id=column-1&p_p_col_count=1&_SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet_javax.portlet.action=incarichiAction',
                    data=payload
                )
                
                payload = {'sceltaincarico': cf_studio + '-000', 'tipoincaricante': 'incDelega', 'cf_inserito': cf_cliente, 'sceltapiva': piva_cliente}
                r = session.post(
                    f'https://ivaservizi.agenziaentrate.gov.it/portale/scelta-utenza-lavoro?p_auth={p_auth}&p_p_id=SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet&p_p_lifecycle=1&p_p_state=normal&p_p_mode=view&p_p_col_id=column-1&p_p_col_count=1&_SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet_javax.portlet.action=incarichiAction',
                    data=payload
                )
            
            return r.status_code == 200
            
        except Exception as e:
            self.logger.error(f"Errore nella selezione utenza: {str(e)}")
            return False
    
    def ottieni_token_servizi(self, session: requests.Session) -> Tuple[str, str]:
        """Ottiene i token necessari per accedere ai servizi"""
        self.logger.info('Ottengo token di servizio...')
        
        # Adesione al servizio
        session.get('https://ivaservizi.agenziaentrate.gov.it/ser/api/fatture/v1/ul/me/adesione/stato/')
        
        # Ottieni token
        headers_token = {
            'x-xss-protection': '1; mode=block',
            'strict-transport-security': 'max-age=16070400; includeSubDomains',
            'x-content-type-options': 'nosniff',
            'x-frame-options': 'deny'
        }
        
        r = session.get(
            'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/sc/tokenB2BCookie/get?v=' + self.unix_time(),
            headers=headers_token
        )
        
        xb2bcookie = r.headers.get('x-b2bcookie')
        xtoken = r.headers.get('x-token')
        
        if not xb2bcookie or not xtoken:
            raise ValueError("Token di servizio non ottenuti")
        
        # Aggiorna headers della sessione
        session.headers.update({
            'Host': 'ivaservizi.agenziaentrate.gov.it',
            'Referer': 'https://ivaservizi.agenziaentrate.gov.it/cons/cons-web/?v=' + self.unix_time(),
            'Accept': 'application/json, text/plain, */*',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7,fr;q=0.6',
            'DNT': '1',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=16070400; includeSubDomains',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'deny',
            'x-b2bcookie': xb2bcookie,
            'x-token': xtoken
        })
        
        # Accetta disclaimer
        session.get(
            'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/disclaimer/accetta?v=' + self.unix_time(),
            headers=headers_token
        )
        
        return xb2bcookie, xtoken
    
    def verifica_disponibilita_corrispettivi(self, session: requests.Session, piva: str, 
                                           data_dal: str, data_al: str) -> bool:
        """Verifica se il cliente ha corrispettivi disponibili"""
        try:
            dal_fmt = datetime.strptime(data_dal, '%d/%m/%Y').strftime('%d%m%Y')
            al_fmt = datetime.strptime(data_al, '%d/%m/%Y').strftime('%d%m%Y')
            
            # Prova a ottenere la sintesi
            url_sintesi = f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/corrispettivi/sintesi/dal/{dal_fmt}/al/{al_fmt}/piva/{piva}?v={self.unix_time()}'
            r = session.get(url_sintesi)
            
            if r.status_code == 404:
                self.logger.info(f"Nessun corrispettivo disponibile per P.IVA {piva}")
                return False
            elif r.status_code != 200:
                self.logger.warning(f"Errore verifica corrispettivi: HTTP {r.status_code}")
                return False
            
            # Verifica se ci sono dati
            try:
                data = json.loads(r.content)
                if data.get('disabilitato', False):
                    self.logger.info(f"Servizio corrispettivi disabilitato per P.IVA {piva}")
                    return False
            except:
                pass
            
            return True
            
        except Exception as e:
            self.logger.error(f"Errore verifica disponibilità: {str(e)}")
            return False
    
    def scarica_corrispettivi(self, session: requests.Session, cliente: Dict[str, Any],
                            data_dal: str, data_al: str) -> Dict[str, Any]:
        """Scarica i corrispettivi telematici per il cliente specificato"""
        
        # Pulizia automatica dei dati (rimuove spazi e caratteri invisibili)
        piva = cliente['partita_iva_diretta'].strip()
        nome_azienda = cliente['nome_azienda'].strip()
        cf_cliente = cliente['codice_fiscale'].strip()
        
        # Risultato dell'operazione
        risultato = {
            'cliente': nome_azienda,
            'piva': piva,
            'periodo': f'{data_dal} - {data_al}',
            'corrispettivi_trovati': 0,
            'corrispettivi_scaricati': 0,
            'corrispettivi_per_tipo': {},
            'tipi_disponibili': [],
            'errori': [],
            'stato': 'completato'
        }
        
        # Verifica disponibilità
        if not self.verifica_disponibilita_corrispettivi(session, piva, data_dal, data_al):
            risultato['stato'] = 'non_disponibile'
            risultato['errori'].append('Corrispettivi non disponibili o servizio disabilitato')
            return risultato
        
        # Formatta le date
        dal_fmt = datetime.strptime(data_dal, '%d/%m/%Y').strftime('%d%m%Y')
        al_fmt = datetime.strptime(data_al, '%d/%m/%Y').strftime('%d%m%Y')
        
        # Estrai mese e anno per la cartella
        data_obj = datetime.strptime(data_dal, '%d/%m/%Y')
        mese = data_obj.strftime('%m')
        anno = data_obj.strftime('%Y')
        
        self.logger.info(f'Scarico corrispettivi per {nome_azienda} (P.IVA {piva}) dal {data_dal} al {data_al}')
        
        # RILEVA AUTOMATICAMENTE TUTTI I TIPI DI CORRISPETTIVI DISPONIBILI
        # Lista completa di tutti i possibili tipi di corrispettivi
        tutti_tipi_corrispettivi = ['RT', 'MC', 'DA', 'DC', 'RC']
        
        # Mappa descrittiva dei tipi
        descrizione_tipi = {
            'RT': 'Registratori Telematici',
            'MC': 'MultiCassa',
            'DA': 'Distributori Automatici',
            'DC': 'Dati Contabili',
            'RC': 'Registratore di Cassa'
        }
        
        tutti_corrispettivi = []
        
        self.logger.info('Rilevamento automatico dei tipi di corrispettivi disponibili...')
        
        # PROVA TUTTI I TIPI DI CORRISPETTIVI PER VEDERE QUALI SONO DISPONIBILI
        for tipo_corrispettivo in tutti_tipi_corrispettivi:
            self.logger.debug(f'Verifico disponibilità tipo {tipo_corrispettivo} ({descrizione_tipi.get(tipo_corrispettivo, tipo_corrispettivo)})')
            
            try:
                # URL per il tipo specifico di corrispettivo
                url_elenco = f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/corrispettivi/sintesi/elenco/dal/{dal_fmt}/al/{al_fmt}/piva/{piva}/tipoCorrispettivo/{tipo_corrispettivo}?v={self.unix_time()}'
                r_elenco = session.get(url_elenco)
                
                if r_elenco.status_code == 200:
                    # Parse del JSON
                    data = json.loads(r_elenco.content)
                    corrispettivi_tipo = data.get('corrispettivi', [])
                    
                    if corrispettivi_tipo:
                        # Aggiungi il tipo a ogni corrispettivo per riferimento
                        for corr in corrispettivi_tipo:
                            corr['tipoCorrispettivo'] = tipo_corrispettivo
                        
                        tutti_corrispettivi.extend(corrispettivi_tipo)
                        risultato['corrispettivi_per_tipo'][tipo_corrispettivo] = len(corrispettivi_tipo)
                        risultato['tipi_disponibili'].append(tipo_corrispettivo)
                        self.logger.info(f'  ✓ Trovati {len(corrispettivi_tipo)} corrispettivi tipo {tipo_corrispettivo} ({descrizione_tipi[tipo_corrispettivo]})')
                    else:
                        self.logger.debug(f'  - Nessun corrispettivo {tipo_corrispettivo} nel periodo')
                elif r_elenco.status_code == 404:
                    self.logger.debug(f'  - Tipo {tipo_corrispettivo} non configurato per questa P.IVA')
                else:
                    self.logger.warning(f'  ⚠ Errore per tipo {tipo_corrispettivo}: HTTP {r_elenco.status_code}')
            
            except Exception as e:
                self.logger.warning(f'  ⚠ Errore nel verificare corrispettivi {tipo_corrispettivo}: {str(e)}')
                continue
        
        risultato['corrispettivi_trovati'] = len(tutti_corrispettivi)
        
        if len(tutti_corrispettivi) == 0:
            self.logger.info(f"Nessun corrispettivo trovato per {nome_azienda} nel periodo specificato")
            risultato['stato'] = 'vuoto'
            return risultato
        
        # Log riepilogo tipi trovati
        if risultato['tipi_disponibili']:
            self.logger.info(f"Tipi di corrispettivi rilevati per {nome_azienda}: {', '.join(risultato['tipi_disponibili'])}")
            
        # Crea la struttura delle cartelle secondo la configurazione
        dir_config = self.config.get('directory_sistema', {})
        base_dir = Path(dir_config.get('output_base', 'aziende_processate'))
        
        # Struttura: output_base/nome_azienda_piva_cf/corrispettivi/mese_anno
        cartella_azienda = base_dir / f'{nome_azienda}_{piva}_{cf_cliente}'
        cartella_corrispettivi = cartella_azienda / 'corrispettivi' / f'{mese}_{anno}'
        cartella_corrispettivi.mkdir(parents=True, exist_ok=True)
        
        # Salva il JSON completo con tutti i tipi di corrispettivi
        json_completo = {
            'periodo': f'{data_dal} - {data_al}',
            'partita_iva': piva,
            'tipi_corrispettivo_disponibili': risultato['tipi_disponibili'],
            'totale_corrispettivi': len(tutti_corrispettivi),
            'corrispettivi_per_tipo': risultato['corrispettivi_per_tipo'],
            'corrispettivi': tutti_corrispettivi
        }
        
        json_path = cartella_corrispettivi / f'elenco_corrispettivi_completo_{mese}_{anno}.json'
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(json_completo, f, indent=2, ensure_ascii=False, default=str)
        self.logger.debug(f'Salvato elenco completo in {json_path}')
            
        # Configurazione performance
        perf_config = self.config.get('configurazione_download', {}).get('performance', {})
        pausa = perf_config.get('pausa_tra_download', 0.5)
        retry_max = perf_config.get('retry_max', 3)
        
        # Gestione file
        file_config = self.config.get('configurazione_download', {}).get('gestione_file', {})
        salta_esistenti = file_config.get('salta_file_esistenti', True)
        
        # 2. Scarica il dettaglio di ogni corrispettivo
        self.logger.info(f'Trovati {len(tutti_corrispettivi)} corrispettivi totali da scaricare')
        if risultato['corrispettivi_per_tipo']:
            for tipo, count in risultato['corrispettivi_per_tipo'].items():
                desc = descrizione_tipi.get(tipo, tipo)
                self.logger.info(f'  • {desc} ({tipo}): {count} corrispettivi')
        
        for idx, corrispettivo in enumerate(tutti_corrispettivi, 1):
            id_invio = corrispettivo.get('idInvio')
            tipo_corr = corrispettivo.get('tipoCorrispettivo', 'RT')
            
            if not id_invio:
                self.logger.warning(f'ID invio mancante per corrispettivo {idx}')
                continue
            
            # Prepara il codice per il download (XX + idInvio)
            codice_download = f'XX{id_invio}'
            
            # Informazioni dal corrispettivo
            data_rilevazione = corrispettivo.get('timeRilevazione', 'data_sconosciuta')
            importo = self.formatta_importo(corrispettivo.get('importo', '0,00'))
            matricola = corrispettivo.get('matricolaDispositivo', 'sconosciuta')
            tipo_dispositivo = corrispettivo.get('tipoDispositivo', '')
            
            # Formatta la data per il nome file
            try:
                data_file = datetime.strptime(data_rilevazione, '%Y-%m-%dT%H:%M:%S').strftime('%Y%m%d_%H%M')
            except:
                data_file = data_rilevazione.replace(':', '').replace('-', '').replace('T', '_')
            
            # Nome file descrittivo con tipo corrispettivo
            nome_file = f'corrispettivo_{tipo_corr}_{data_file}_id{id_invio}_euro{importo.replace(",", "_")}_matr{matricola}.xml'
            file_path = cartella_corrispettivi / nome_file
            
            # Verifica se saltare file esistenti
            if salta_esistenti and file_path.exists():
                self.logger.debug(f'File già esistente, salto: {nome_file}')
                risultato['corrispettivi_scaricati'] += 1
                continue
            
            # Download con retry
            for tentativo in range(retry_max):
                try:
                    url_dettaglio = f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/corrispettivi/dettaglio/{codice_download}?v={self.unix_time()}'
                    r_dettaglio = session.get(url_dettaglio)
                    
                    if r_dettaglio.status_code == 200:
                        with open(file_path, 'wb') as f:
                            f.write(r_dettaglio.content)
                        
                        self.logger.info(f'  [{idx}/{len(tutti_corrispettivi)}] {tipo_corr}: Salvato {nome_file}')
                        risultato['corrispettivi_scaricati'] += 1
                        break
                    else:
                        if tentativo == retry_max - 1:
                            errore = f'Errore download dettaglio {id_invio}: HTTP {r_dettaglio.status_code}'
                            self.logger.error(errore)
                            risultato['errori'].append(errore)
                        else:
                            time.sleep(1)
                
                except Exception as e:
                    if tentativo == retry_max - 1:
                        errore = f'Errore download dettaglio {id_invio}: {str(e)}'
                        self.logger.error(errore)
                        risultato['errori'].append(errore)
                    else:
                        time.sleep(1)
            
            # Pausa tra download
            if pausa > 0:
                time.sleep(pausa)
        
        # 3. Crea riepilogo dettagliato
        self._crea_riepilogo(cartella_corrispettivi, tutti_corrispettivi, risultato, 
                           nome_azienda, piva, data_dal, data_al, mese, anno)
        
        self.logger.info(f'Completato: {risultato["corrispettivi_scaricati"]}/{risultato["corrispettivi_trovati"]} corrispettivi scaricati')
        
        return risultato
    
    def _crea_riepilogo(self, cartella: Path, corrispettivi: list, risultato: dict,
                       nome_azienda: str, piva: str, data_dal: str, data_al: str, 
                       mese: str, anno: str):
        """Crea file di riepilogo dettagliato"""
        
        # Calcola totali per tipo
        totali_per_tipo = {}
        giorni_attivi = set()
        giorni_inattivi = []
        
        # Mappa descrittiva dei tipi
        descrizione_tipi = {
            'RT': 'Registratori Telematici',
            'MC': 'MultiCassa',
            'DA': 'Distributori Automatici',
            'DC': 'Dati Contabili',
            'RC': 'Registratore di Cassa'
        }
        
        riepilogo = {
            'azienda': {
                'nome': nome_azienda,
                'partita_iva': piva,
                'periodo': f'{data_dal} - {data_al}'
            },
            'statistiche': {
                'totale_corrispettivi': len(corrispettivi),
                'corrispettivi_scaricati': risultato['corrispettivi_scaricati'],
                'corrispettivi_per_tipo': risultato.get('corrispettivi_per_tipo', {}),
                'giorni_attivi': 0,
                'giorni_inattivi': 0,
                'totale_incassato': 0.0,
                'totali_per_tipo': {}
            },
            'dettaglio_corrispettivi': []
        }
        
        for corr in corrispettivi:
            # Tipo corrispettivo
            tipo_corr = corr.get('tipoCorrispettivo', 'RT')
            
            # Inizializza totale per tipo se non esiste
            if tipo_corr not in totali_per_tipo:
                totali_per_tipo[tipo_corr] = {
                    'descrizione': descrizione_tipi.get(tipo_corr, tipo_corr),
                    'numero': 0,
                    'importo_totale': 0.0,
                    'matricole': set()
                }
            
            # Estrai importo numerico
            try:
                importo_str = self.formatta_importo(corr.get('importo', '0,00'))
                importo_num = float(importo_str.replace(',', '.'))
                totali_per_tipo[tipo_corr]['importo_totale'] += importo_num
                totali_per_tipo[tipo_corr]['numero'] += 1
            except:
                importo_num = 0.0
            
            # Aggiungi matricola al set
            matricola = corr.get('matricolaDispositivo')
            if matricola:
                totali_per_tipo[tipo_corr]['matricole'].add(matricola)
            
            # Gestione date
            data_rilevazione = corr.get('timeRilevazione', '')
            if data_rilevazione:
                try:
                    data_obj = datetime.strptime(data_rilevazione, '%Y-%m-%dT%H:%M:%S')
                    giorni_attivi.add(data_obj.date())
                except:
                    pass
            
            # Gestione inattività
            inattivita_dal = corr.get('inattivitaDal')
            inattivita_al = corr.get('inattivitaAl')
            if inattivita_dal and inattivita_al:
                giorni_inattivi.append({
                    'dal': inattivita_dal,
                    'al': inattivita_al
                })
            
            # Aggiungi dettaglio
            riepilogo['dettaglio_corrispettivi'].append({
                'id_invio': corr.get('idInvio'),
                'tipo_corrispettivo': tipo_corr,
                'descrizione_tipo': descrizione_tipi.get(tipo_corr, tipo_corr),
                'data_rilevazione': data_rilevazione,
                'importo': importo_num,
                'matricola': corr.get('matricolaDispositivo'),
                'tipo_dispositivo': corr.get('tipoDispositivo'),
                'inattivita': {
                    'dal': inattivita_dal,
                    'al': inattivita_al
                } if inattivita_dal else None
            })
        
        # Calcola totale generale
        totale_generale = sum(t['importo_totale'] for t in totali_per_tipo.values())
        
        # Converti set matricole in lista per JSON
        for tipo in totali_per_tipo.values():
            tipo['matricole'] = list(tipo['matricole'])
        
        # Aggiorna statistiche
        riepilogo['statistiche']['giorni_attivi'] = len(giorni_attivi)
        riepilogo['statistiche']['giorni_inattivi'] = len(giorni_inattivi)
        riepilogo['statistiche']['totale_incassato'] = round(totale_generale, 2)
        riepilogo['statistiche']['media_giornaliera'] = round(totale_generale / len(giorni_attivi), 2) if giorni_attivi else 0
        riepilogo['statistiche']['totali_per_tipo'] = totali_per_tipo
        
        # Salva riepilogo
        riepilogo_path = cartella / f'riepilogo_corrispettivi_{mese}_{anno}.json'
        with open(riepilogo_path, 'w', encoding='utf-8') as f:
            json.dump(riepilogo, f, indent=2, ensure_ascii=False, default=str)
        
        self.logger.info(f'Riepilogo salvato in {riepilogo_path}')
    
    def processa_cliente(self, cliente_id: str, cliente_data: Dict[str, Any], 
                        data_dal: str, data_al: str) -> Dict[str, Any]:
        """Processa un singolo cliente"""
        
        risultato = {
            'cliente_id': cliente_id,
            'nome': cliente_data['nome_azienda'],
            'stato': 'non_processato',
            'dettagli': {}
        }
        
        # Verifica se il cliente è attivo
        if not cliente_data.get('attivo', True):
            self.logger.info(f"Cliente {cliente_data['nome_azienda']} non attivo, salto")
            risultato['stato'] = 'non_attivo'
            return risultato
        
        # Verifica se ha corrispettivi abilitati
        if not cliente_data.get('corrispettivi_abilitati', True):
            self.logger.info(f"Corrispettivi non abilitati per {cliente_data['nome_azienda']}, salto")
            risultato['stato'] = 'corrispettivi_disabilitati'
            return risultato
        
        self.logger.info(f"\n{'='*60}")
        self.logger.info(f"Processo cliente: {cliente_data['nome_azienda']}")
        self.logger.info(f"{'='*60}")
        
        # Crea sessione
        session = self.crea_sessione()
        
        try:
            # Login
            p_auth = self.login_agenzia_entrate(session)
            self.logger.info('✓ Login completato')
            
            # Seleziona utenza
            if not self.seleziona_utenza(session, p_auth, cliente_data):
                raise ValueError("Impossibile selezionare utenza")
            self.logger.info('✓ Utenza selezionata')
            
            # Ottieni token
            xb2bcookie, xtoken = self.ottieni_token_servizi(session)
            self.logger.info('✓ Token ottenuti')
            
            # Scarica corrispettivi
            risultato['dettagli'] = self.scarica_corrispettivi(
                session, cliente_data, data_dal, data_al
            )
            
            risultato['stato'] = risultato['dettagli'].get('stato', 'completato')
            
        except Exception as e:
            errore = f'Errore per cliente {cliente_data["nome_azienda"]}: {str(e)}'
            self.logger.error(errore)
            risultato['stato'] = 'errore'
            risultato['dettagli'] = {'errore': str(e)}
        
        finally:
            session.close()
        
        return risultato
    
    def esegui(self, data_dal: Optional[str] = None, data_al: Optional[str] = None):
        """Esegue il download dei corrispettivi per tutti i clienti configurati"""
        
        # Gestione date con priorità: parametri > config > default
        if not data_dal or not data_al:
            # Prova a leggere dal file di configurazione
            periodo_config = self.config.get('periodo_elaborazione', {})
            
            if periodo_config.get('usa_periodo_corrente', False):
                # Usa periodo corrente
                oggi = datetime.now()
                if periodo_config.get('giorni_indietro_default'):
                    giorni = periodo_config['giorni_indietro_default']
                    data_dal = (oggi - timedelta(days=giorni)).strftime('%d/%m/%Y')
                    data_al = oggi.strftime('%d/%m/%Y')
                else:
                    # Usa il mese corrente
                    primo_giorno = oggi.replace(day=1)
                    data_dal = primo_giorno.strftime('%d/%m/%Y')
                    data_al = oggi.strftime('%d/%m/%Y')
            else:
                # Usa date dal file di configurazione
                data_dal = periodo_config.get('data_inizio')
                data_al = periodo_config.get('data_fine')
                
                # Se ancora non ci sono date, usa default
                if not data_dal or not data_al:
                    oggi = datetime.now()
                    primo_giorno = oggi.replace(day=1)
                    data_dal = primo_giorno.strftime('%d/%m/%Y')
                    data_al = oggi.strftime('%d/%m/%Y')
                    self.logger.info(f"Date non specificate, uso periodo di default: {data_dal} - {data_al}")
        
        self.logger.info(f"Inizio elaborazione corrispettivi dal {data_dal} al {data_al}")
        
        # Ottieni portfolio clienti
        portfolio = self.config.get('portfolio_clienti', {})
        clienti_totali = len(portfolio)
        
        if clienti_totali == 0:
            self.logger.warning("Nessun cliente configurato nel portfolio")
            return
        
        self.logger.info(f"Trovati {clienti_totali} clienti da processare")
        
        # Report finale
        report = {
            'data_elaborazione': datetime.now().isoformat(),
            'periodo': f'{data_dal} - {data_al}',
            'clienti_totali': clienti_totali,
            'clienti_processati': 0,
            'clienti_con_corrispettivi': 0,
            'totale_corrispettivi_scaricati': 0,
            'errori': [],
            'dettaglio_clienti': []
        }
        
        # Processa ogni cliente
        for cliente_id, cliente_data in portfolio.items():
            risultato = self.processa_cliente(cliente_id, cliente_data, data_dal, data_al)
            
            report['dettaglio_clienti'].append(risultato)
            
            if risultato['stato'] == 'completato':
                report['clienti_processati'] += 1
                if risultato['dettagli'].get('corrispettivi_scaricati', 0) > 0:
                    report['clienti_con_corrispettivi'] += 1
                    report['totale_corrispettivi_scaricati'] += risultato['dettagli']['corrispettivi_scaricati']
            elif risultato['stato'] == 'errore':
                report['errori'].append({
                    'cliente': risultato['nome'],
                    'errore': risultato['dettagli'].get('errore', 'Errore sconosciuto')
                })
            
            # Pausa tra clienti
            perf_config = self.config.get('configurazione_download', {}).get('performance', {})
            pausa = perf_config.get('pausa_tra_download', 0.5)
            if pausa > 0:
                time.sleep(pausa * 2)  # Pausa doppia tra clienti
        
        # Salva report
        self._salva_report(report)
        
        # Stampa riepilogo
        self.logger.info("\n" + "="*60)
        self.logger.info("RIEPILOGO ELABORAZIONE")
        self.logger.info("="*60)
        self.logger.info(f"Clienti totali: {report['clienti_totali']}")
        self.logger.info(f"Clienti processati: {report['clienti_processati']}")
        self.logger.info(f"Clienti con corrispettivi: {report['clienti_con_corrispettivi']}")
        self.logger.info(f"Totale corrispettivi scaricati: {report['totale_corrispettivi_scaricati']}")
        if report['errori']:
            self.logger.warning(f"Errori riscontrati: {len(report['errori'])}")
        self.logger.info("="*60)
    
    def _salva_report(self, report: Dict[str, Any]):
        """Salva il report dell'elaborazione"""
        
        # Directory reports
        report_dir = Path(self.config.get('directory_sistema', {}).get('reports', 'reports_sistema'))
        report_dir.mkdir(parents=True, exist_ok=True)
        
        # Nome file con timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = report_dir / f'report_corrispettivi_{timestamp}.json'
        
        # Salva report
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        
        self.logger.info(f"Report salvato in {report_file}")


def main():
    """Funzione principale"""
    
    # Parser argomenti
    import argparse
    parser = argparse.ArgumentParser(description='Download corrispettivi telematici da Agenzia Entrate')
    parser.add_argument('--config', default='config_ade_system.json', 
                       help='Path al file di configurazione')
    parser.add_argument('--dal', help='Data inizio (dd/mm/yyyy)')
    parser.add_argument('--al', help='Data fine (dd/mm/yyyy)')
    parser.add_argument('--aggiorna-config', action='store_true',
                       help='Aggiorna il file di configurazione per includere i corrispettivi')
    
    args = parser.parse_args()
    
    # Se richiesto aggiornamento configurazione
    if args.aggiorna_config:
        aggiorna_configurazione(args.config)
        return
    
    # Esegui download
    try:
        downloader = CorrispettiviDownloader(args.config)
        downloader.esegui(args.dal, args.al)
    except FileNotFoundError:
        print(f"File di configurazione {args.config} non trovato!")
        print("Usa --aggiorna-config per aggiornare la configurazione esistente")
    except Exception as e:
        print(f"Errore: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


def aggiorna_configurazione(config_path: str):
    """Aggiorna il file di configurazione per includere il supporto ai corrispettivi"""
    
    if not os.path.exists(config_path):
        print(f"File {config_path} non trovato!")
        return
    
    # Carica configurazione esistente
    with open(config_path, 'r', encoding='utf-8') as f:
        config = json.load(f)
    
    # Aggiungi supporto corrispettivi ai tipi di documenti
    if 'configurazione_download' in config:
        if 'tipi_documenti' in config['configurazione_download']:
            config['configurazione_download']['tipi_documenti']['corrispettivi_telematici'] = True
            print("✓ Aggiunto supporto corrispettivi telematici ai tipi di documenti")
    
    # Aggiungi flag corrispettivi_abilitati a ogni cliente
    if 'portfolio_clienti' in config:
        for cliente_id, cliente_data in config['portfolio_clienti'].items():
            if 'corrispettivi_abilitati' not in cliente_data:
                cliente_data['corrispettivi_abilitati'] = True
                print(f"✓ Abilitati corrispettivi per {cliente_data['nome_azienda']}")
    
    # Aggiorna versione configurazione
    if 'metadata' in config:
        config['metadata']['versione_config'] = '2.2.0'
        config['metadata']['ultima_modifica'] = datetime.now().strftime('%Y-%m-%d')
        config['metadata']['note_versione'] = 'Aggiunto supporto corrispettivi telematici'
    
    # Salva backup
    backup_path = config_path.replace('.json', f'_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json')
    with open(backup_path, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    print(f"✓ Backup salvato in {backup_path}")
    
    # Salva configurazione aggiornata
    with open(config_path, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    print(f"✓ Configurazione aggiornata in {config_path}")
    
    print("\nConfigurazione aggiornata con successo!")
    print("Ora puoi eseguire lo script per scaricare i corrispettivi.")


if __name__ == "__main__":
    main()