## Licenza Libera progetto originario di Claudio Pizzillo
## Modifiche e riadattamenti da Salvatore Crapanzano
## 01/08/23 Altre modifiche da Uzirox## 
## V. 4.2.5 del 12-08-2025  - Emesse: FILE_FATTURA + METADATI in *_p7m; decodificati in base; supporto BASE_DIR (es. C:\SCARICA)

import subprocess
from datetime import timedelta, datetime
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import re
import sys
import pytz
import json
import os
import shutil
from clint.textui import colored, puts
from tqdm import tqdm
from typing import Optional, Tuple

# ---------- Config opzionali ----------
# Se metti a True, oltre a salvare i metadati nello _p7m per le EMESSE,
# ne verrà fatta una **copia** anche nella cartella base accanto alla fattura decodificata.
COPY_META_EMESSE_ALSO_IN_BASE = True

# ---------- Utility ----------

def aggiusta_fine_trimestre(d):
    """Ritorna l'ultimo giorno del trimestre della data d."""
    if d.month < 4:
        return datetime(d.year, 3, 31)
    elif d.month < 7:
        return datetime(d.year, 6, 30)
    elif d.month < 10:
        return datetime(d.year, 9, 30)
    else:
        return datetime(d.year, 12, 31)

def divide_in_trimestri(data_iniziale, data_finale):
    """
    Divide l'intervallo [data_iniziale, data_finale] (formato ddmmyyyy) in sotto-intervalli trimestrali chiusi.
    """
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

def unixTime():
    dt = datetime.now(tz=pytz.utc)
    return str(int(dt.timestamp() * 1000))

def ensure_dir(path):
    os.makedirs(path, exist_ok=True)

def base_join(base_dir: str, *parts: str) -> str:
    return os.path.normpath(os.path.join(base_dir, *parts))

def mk_paths(kind: str, cfcliente: str, base_dir: str) -> Tuple[str, str]:
    """
    Ritorna (dec_dir, raw_dir) per il tipo di cartella richiesto.
    kind in {"Ricevute","Emesse"} (le transfrontaliere riusano Ricevute/Emesse)
    """
    dec = base_join(base_dir, f"Fatture{kind}_{cfcliente}")
    raw = dec + "_p7m"
    return dec, raw

def parse_filename_from_cd(cd_value: str) -> Optional[str]:
    """
    Estrae il filename dall'header Content-Disposition (gestisce sia filename che filename*).
    Restituisce None se non presente.
    """
    if not cd_value:
        return None
    # RFC5987 filename* e fallback filename=
    m = re.search(r"filename\*\s*=\s*(?:UTF-8''|utf-8'')?\"?([^\";]+)\"?", cd_value, flags=re.IGNORECASE)
    if not m:
        m = re.search(r'filename\s*=\s*"?([^\";]+)"?', cd_value, flags=re.IGNORECASE)
    return m.group(1) if m else None

def stream_to_file(resp, fullpath, label):
    """Scarica in streaming resp.content su fullpath con progress bar."""
    total_size = int(resp.headers.get('content-length', 0))
    ensure_dir(os.path.dirname(fullpath))
    with open(fullpath, 'wb') as f, tqdm(total=total_size, unit='B', unit_divisor=1024, unit_scale=True, ascii=True) as pbar:
        pbar.set_description(f"Scarico {label}")
        for chunk in resp.iter_content(chunk_size=1024):
            if chunk:
                f.write(chunk)
                pbar.update(len(chunk))

def build_metadato_name_from_invoice(invoice_filename: str) -> str:
    """
    Crea il nome del metadato partendo dal NOME FILE DELLA FATTURA,
    aggiungendo il postfisso '_metadato.xml'.
    """
    return f"{invoice_filename}_metadato.xml"

def decrypt_p7m_files(input_dir, output_dir):
    """
    Decripta i file .p7m in input_dir e salva in output_dir rimuovendo l'estensione .p7m.
    Copia anche i .xml non metadato nella stessa output_dir.
    """
    if not os.path.exists(input_dir) or not os.path.isdir(input_dir):
        print(f"La directory di input {input_dir} non esiste o non è una directory.")
        return
    ensure_dir(output_dir)

    entries = os.listdir(input_dir)
    if not entries:
        print(f"Nessun file trovato in {input_dir}.")
        return

    for filename in entries:
        src = os.path.join(input_dir, filename)
        if filename.lower().endswith(".p7m"):
            base, _ = os.path.splitext(filename)  # rimuove solo .p7m (mantiene eventuale .xml)
            dst = os.path.join(output_dir, base)
            command = f'openssl cms -decrypt -verify -inform DER -in "{src}" -noverify -out "{dst}"'
            print(command)
            try:
                subprocess.run(command, shell=True, check=True)
                print(f"Decriptazione e verifica di {filename} completate con successo.")
            except subprocess.CalledProcessError as e:
                print(f"Errore durante la decriptazione del file {filename}: {e}")
        elif filename.lower().endswith(".xml") and not filename.lower().endswith("_metadato.xml"):
            shutil.copy(src, os.path.join(output_dir, filename))

# ---------- Download wrappers ----------

def scarica_file_fattura(session, url, headers_token, dest_dir) -> Optional[str]:
    """
    Scarica il FILE_FATTURA. Ritorna il nome file fattura (così come da header) se ok; altrimenti None.
    """
    with session.get(url, headers=headers_token, stream=True) as r:
        if r.status_code != 200:
            return None
        invoice_filename = parse_filename_from_cd(r.headers.get('content-disposition')) or "fattura_senza_nome.xml"
        fullpath = os.path.join(dest_dir, invoice_filename)
        stream_to_file(r, fullpath, f"fattura: {invoice_filename}")
        return invoice_filename

def salva_file_metadati(session, url, headers_token, dest_dir, invoice_filename: str):
    """
    Scarica il FILE_METADATI con nome: <invoice_filename>_metadato.xml nel dest_dir.
    """
    with session.get(url, headers=headers_token, stream=True) as r:
        if r.status_code != 200:
            return False
        renamed_meta_name = build_metadato_name_from_invoice(invoice_filename)
        fullpath_renamed = os.path.join(dest_dir, renamed_meta_name)
        stream_to_file(r, fullpath_renamed, f"metadato: {renamed_meta_name}")
        return True

# ---------- Blocco principale ----------

try:
    # Argomenti richiesti (11) + opzionale BASE_DIR (12°)
    if len(sys.argv) < 11:
        print('Utilizzo: fec.py CF PIN PASSWORD COD_FISCALE DataDal DataAl CF_CLIENTE PIVA_CLIENTE TIPO VenOAcq [BASE_DIR]')
        print('TIPO: 1 = solo data RICEZIONE; 2 = solo data EMISSIONE; 3 = ENTRAMBI')
        print(r'Esempio (BASE_DIR): py fec.py CF PIN PASS COD 01012025 31032025 CFCLI PIVA 3 T C:\SCARICA')
        sys.exit(1)

    profilo = 1  # 1: Delega diretta, 2: Me stesso, 3: Studio Associato
    CF = sys.argv[1]
    PIN = sys.argv[2]
    Password  = sys.argv[3]
    cfstudio  = sys.argv[4]
    Dal = sys.argv[5]
    Al = sys.argv[6]
    cfcliente = sys.argv[7]
    pivadiretta = sys.argv[8]
    tipo = int(sys.argv[9])          # 1=ricezione, 2=emissione, 3=entrambi
    VenOAcq = sys.argv[10].upper()   # "V" vendite, "A" acquisti, "T" entrambi
    base_dir = sys.argv[11] if len(sys.argv) > 11 else os.getcwd()
    base_dir = os.path.normpath(base_dir)

    if tipo not in (1,2,3):
        print("Valore TIPO non valido. Usa: 1=ricezione, 2=emissione, 3=entrambi")
        sys.exit(1)

    trimestri = divide_in_trimestri(Dal, Al)
    print(trimestri)

    for data_iniziale_trimestre, data_finale_trimestre in trimestri:
        print(f"Elaborazione del periodo {data_iniziale_trimestre} - {data_finale_trimestre}")

        s = requests.Session()
        s.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.119 Safari/537.36',
            'Connection': 'keep-alive'
        })
        # Cookie iniziali
        s.cookies.set_cookie(requests.cookies.create_cookie(domain='ivaservizi.agenziaentrate.gov.it', name='LFR_SESSION_STATE_20159', value='expired'))
        s.cookies.set_cookie(requests.cookies.create_cookie(domain='ivaservizi.agenziaentrate.gov.it', name='LFR_SESSION_STATE_10811916', value=unixTime()))

        r = s.get('https://ivaservizi.agenziaentrate.gov.it/portale/web/guest', verify=False)
        if r.status_code == 200:
            puts(colored.yellow('Collegamento alla homepage. Avvio.'))
        else:
            puts(colored.red('Collegamento alla homepage non riuscito: uscita.'))
            sys.exit(1)

        # Login
        print('Effettuo il login')
        payload = {
            '_58_saveLastPath': 'false', '_58_redirect' : '', '_58_doActionAfterLogin': 'false',
            '_58_login': CF , '_58_pin': PIN, '_58_password': Password
        }    
        r = s.post('https://ivaservizi.agenziaentrate.gov.it/portale/home?p_p_id=58&p_p_lifecycle=1&p_p_state=normal&p_p_mode=view&p_p_col_id=column-1&p_p_col_pos=3&p_p_col_count=4&_58_struts_action=%2Flogin%2Flogin', data=payload)

        liferay_m = re.search(r"Liferay\.authToken = '([^']+)';", r.text)
        if not liferay_m:
            puts(colored.red('Token Liferay non trovato: uscita.'))
            sys.exit(1)
        p_auth = liferay_m.group(1)

        r = s.get('https://ivaservizi.agenziaentrate.gov.it/dp/api?v=' + unixTime())
        if r.status_code == 200:
            puts(colored.yellow('Login riuscito. Con credenziali ENTRATEL'))
        else:
            puts(colored.red('Login non riuscito: uscita.')) 
            sys.exit(1)

        # Scelta utenza
        print('Seleziono il tipo di incarico')
        if profilo == 1:
            # Delega Diretta
            payload = {'cf_inserito': cfcliente}
            s.post(f'https://ivaservizi.agenziaentrate.gov.it/portale/scelta-utenza-lavoro?p_auth={p_auth}&p_p_id=SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet&p_p_lifecycle=1&p_p_state=normal&p_p_mode=view&p_p_col_id=column-1&p_p_col_count=1&_SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet_javax.portlet.action=delegaDirettaAction', data=payload)
            payload = {'cf_inserito': cfcliente, 'sceltapiva': pivadiretta}
            s.post(f'https://ivaservizi.agenziaentrate.gov.it/portale/scelta-utenza-lavoro?p_auth={p_auth}&p_p_id=SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet&p_p_lifecycle=1&p_p_state=normal&p_p_mode=view&p_p_col_id=column-1&p_p_col_count=1&_SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet_javax.portlet.action=delegaDirettaAction', data=payload)
        elif profilo == 2:
            # Me stesso
            payload = {'sceltaincarico': cfstudio + '-000', 'tipoincaricante' : 'incDiretto'}
            s.post(f'https://ivaservizi.agenziaentrate.gov.it/portale/scelta-utenza-lavoro?p_auth={p_auth}&p_p_id=SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet&p_p_lifecycle=1&p_p_state=normal&p_p_mode=view&p_p_col_id=column-1&p_p_col_count=1&_SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet_javax.portlet.action=meStessoAction', data=payload)
            payload = {'sceltaincarico': cfstudio + '-000', 'tipoincaricante' : 'incDiretto', 'sceltapiva' : pivadiretta}
            s.post(f'https://ivaservizi.agenziaentrate.gov.it/portale/scelta-utenza-lavoro?p_auth={p_auth}&p_p_id=SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet&p_p_lifecycle=1&p_p_state=normal&p_p_mode=view&p_p_col_id=column-1&p_p_col_count=1&_SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet_javax.portlet.action=meStessoAction', data=payload)
        else:
            # Studio Associato
            payload = {'sceltaincarico': cfstudio + '-000', 'tipoincaricante' : 'incDelega', 'cf_inserito': cfcliente}
            s.post(f'https://ivaservizi.agenziaentrate.gov.it/portale/scelta-utenza-lavoro?p_auth={p_auth}&p_p_id=SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet&p_p_lifecycle=1&p_p_state=normal&p_p_mode=view&p_p_col_id=column-1&p_p_col_count=1&_SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet_javax.portlet.action=incarichiAction', data=payload)
            payload = {'sceltaincarico': cfstudio + '-000', 'tipoincaricante' : 'incDelega', 'cf_inserito': cfcliente, 'sceltapiva' : pivadiretta}
            s.post(f'https://ivaservizi.agenziaentrate.gov.it/portale/scelta-utenza-lavoro?p_auth={p_auth}&p_p_id=SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet&p_p_lifecycle=1&p_p_state=normal&p_p_mode=view&p_p_col_id=column-1&p_p_col_count=1&_SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet_javax.portlet.action=incarichiAction', data=payload)

        # Adesione
        print('Aderisco al servizio')
        r = s.get('https://ivaservizi.agenziaentrate.gov.it/ser/api/fatture/v1/ul/me/adesione/stato/')
        if r.status_code == 200:
            puts(colored.yellow('Adesione riuscita ai servizi AdE.'))
        else:
            puts(colored.red('Adesione ai servizi AdE non riuscita: uscita.')) 
            sys.exit(1)

        headers_token = {
            'x-xss-protection': '1; mode=block',
            'strict-transport-security': 'max-age=16070400; includeSubDomains',
            'x-content-type-options': 'nosniff',
            'x-frame-options': 'deny'
        }
        r = s.get('https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/sc/tokenB2BCookie/get?v='+unixTime(), headers=headers_token)
        if r.status_code != 200:
            puts(colored.red('B2B Cookie non ottenuto: uscita.'))
            sys.exit(1)

        xb2bcookie = r.headers.get('x-b2bcookie')
        xtoken = r.headers.get('x-token')

        s.headers.update({
            'Host': 'ivaservizi.agenziaentrate.gov.it',
            'Referer': 'https://ivaservizi.agenziaentrate.gov.it/cons/cons-web/?v=' + unixTime(),
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
        headers = {
            'Host': 'ivaservizi.agenziaentrate.gov.it',
            'referer': 'https://ivaservizi.agenziaentrate.gov.it/cons/cons-web/?v=' + unixTime(),
            'accept': 'application/json, text/plain, */*',
            'accept-encoding': 'gzip, deflate, br',
            'accept-language': 'it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7,fr;q=0.6',
            'DNT': '1',
            'x-xss-protection': '1; mode=block',
            'strict-transport-security': 'max-age=16070400; includeSubDomains',
            'x-content-type-options': 'nosniff',
            'x-frame-options': 'deny',
            'x-b2bcookie': xb2bcookie,
            'x-token': xtoken,
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.119 Safari/537.36'
        }

        print('Accetto le condizioni')
        s.get('https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/disclaimer/accetta?v='+unixTime(), headers=headers_token)

        # ===================================
        # BLOCCO ACQUISTI (non V)  [applica BASE_DIR]
        # ===================================
        if VenOAcq != "V":
            # -- Fatture messe a disposizione --
            print('Scarico il json delle fatture ricevute e messe a disposizione per la partita IVA ' + cfcliente)
            r = s.get(f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fe/mc/dal/{data_iniziale_trimestre}/al/{data_finale_trimestre}?v=' + unixTime(), headers=headers)
            if r.status_code == 200:
                puts(colored.yellow('Lista ottenuta FATTURE A DISPOSIZIONE (può essere vuota)'))
            else:
                puts(colored.red('Lista FATTURE A DISPOSIZIONE non ottenuta: uscita.'))
                sys.exit(1)

            with open(base_join(base_dir, 'fe_ricevute_disposizione_' + cfcliente + '.json'), 'wb') as f:
                f.write(r.content)

            dec_dir, raw_dir = mk_paths("Ricevute", cfcliente, base_dir)
            ensure_dir(raw_dir); ensure_dir(dec_dir)

            numero_fatture_disposizione = 0
            data_mc = r.json()
            for fattura in data_mc.get('fatture', []):
                fatturaFile = fattura['tipoInvio'] + fattura['idFattura']
                url_fatt = f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fatture/file/{fatturaFile}?tipoFile=FILE_FATTURA&download=1&v=' + unixTime()
                inv_name = scarica_file_fattura(s, url_fatt, headers_token, raw_dir)
                if inv_name:
                    numero_fatture_disposizione += 1

            decrypt_p7m_files(raw_dir, dec_dir)

            with open(base_join(base_dir, 'output_fatture.txt'), 'a', encoding='utf-8') as file:
                print('Totale fatture messe a disposizione scaricate:', numero_fatture_disposizione, cfcliente, file=file)
                print('Cartelle:', {'raw': raw_dir, 'decodificate': dec_dir}, file=file)

            # -- Fatture passive ricevute per data ricezione / emissione --
            def scarica_passive(tipo_local):
                print(('Scarico il json delle fatture ricevute per data RICEZIONE' if tipo_local == 1 else 'Scarico il json delle fatture ricevute per data EMISSIONE') + ' per ' + cfcliente)
                if tipo_local == 1:
                    url = f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fe/ricevute/dal/{data_iniziale_trimestre}/al/{data_finale_trimestre}/ricerca/ricezione?v=' + unixTime()
                else:
                    url = f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fe/ricevute/dal/{data_iniziale_trimestre}/al/{data_finale_trimestre}/ricerca/emissione?v=' + unixTime()

                resp = s.get(url, headers=headers)
                with open(base_join(base_dir, f'fe_ricevute_{cfcliente}_tipo{tipo_local}.json'), 'wb') as f:
                    f.write(resp.content)

                puts(colored.red('Inizio a scaricare le fatture PASSIVE ricevute per tipo ' + colored.green(str(tipo_local))))
                dec_dir, raw_dir = mk_paths("Ricevute", cfcliente, base_dir)
                ensure_dir(raw_dir); ensure_dir(dec_dir)

                data_j = resp.json()
                n_fatt, n_meta = 0, 0
                for fattura in data_j.get('fatture', []):
                    fatturaFile = fattura['tipoInvio'] + fattura['idFattura']

                    url_fatt = f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fatture/file/{fatturaFile}?tipoFile=FILE_FATTURA&download=1&v=' + unixTime()
                    invoice_filename = scarica_file_fattura(s, url_fatt, headers_token, raw_dir)
                    if invoice_filename:
                        n_fatt += 1

                        url_meta = f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fatture/file/{fatturaFile}?tipoFile=FILE_METADATI&download=1&v=' + unixTime()
                        ok = salva_file_metadati(s, url_meta, headers_token, dec_dir, invoice_filename)
                        if ok:
                            n_meta += 1

                decrypt_p7m_files(raw_dir, dec_dir)

                with open(base_join(base_dir, 'output_fatture.txt'), 'a', encoding='utf-8') as file:
                    print('Trimestre:', (data_iniziale_trimestre, data_finale_trimestre), file=file)
                    print('Totale PASSIVE RICEVUTE:', n_fatt, ' metadati:', n_meta, file=file)

            if tipo in (1,3):
                scarica_passive(1)
            if tipo in (2,3):
                scarica_passive(2)

        # ===================================
        # BLOCCO VENDITE (non A)  [EMESSE con logica richiesta]
        # ===================================
        if VenOAcq != "A":
            print('Scarico il json delle fatture EMESSE per la P.IVA ' + cfcliente)
            r = s.get(f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fe/emesse/dal/{data_iniziale_trimestre}/al/{data_finale_trimestre}?v=' + unixTime(), headers=headers)
            with open(base_join(base_dir, 'fe_emesse_' + cfcliente + '.json'), 'wb') as f:
                f.write(r.content)

            dec_dir, raw_dir = mk_paths("Emesse", cfcliente, base_dir)
            ensure_dir(raw_dir); ensure_dir(dec_dir)

            n_fatt_e, n_meta_e = 0, 0
            data_em = r.json()

            for fattura in data_em.get('fatture', []):
                fatturaFile = fattura['tipoInvio'] + fattura['idFattura']

                # ORIGINALI in _p7m
                url_fatt = f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fatture/file/{fatturaFile}?tipoFile=FILE_FATTURA&download=1&v=' + unixTime()
                invoice_filename = scarica_file_fattura(s, url_fatt, headers_token, raw_dir)
                if invoice_filename:
                    n_fatt_e += 1

                    # METADATI: per richiesta tua, in _p7m (raw) con naming coerente
                    url_meta = f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fatture/file/{fatturaFile}?tipoFile=FILE_METADATI&download=1&v=' + unixTime()
                    if salva_file_metadati(s, url_meta, headers_token, raw_dir, invoice_filename):
                        n_meta_e += 1
                        if COPY_META_EMESSE_ALSO_IN_BASE:
                            # Copia anche in base per pairing con la fattura decodificata
                            src = os.path.join(raw_dir, build_metadato_name_from_invoice(invoice_filename))
                            dst = os.path.join(dec_dir, build_metadato_name_from_invoice(invoice_filename))
                            try:
                                shutil.copyfile(src, dst)
                            except Exception as e:
                                print(f"Impossibile copiare metadato in base: {e}")

            # decodifica verso cartella base
            decrypt_p7m_files(raw_dir, dec_dir)

            with open(base_join(base_dir, 'output_fatture.txt'), 'a', encoding='utf-8') as file:
                print('Per il cliente:', cfcliente, file=file)
                print('EMESSE - fatture:', n_fatt_e, ' metadati:', n_meta_e, file=file)

        # ===================================
        # BLOCCO TRANSFRONTALIERE (applica BASE_DIR e preserva originali)
        # ===================================
        if VenOAcq != "A":
            # Transfrontaliere EMESSE
            print('Scarico il json delle fatture Transfrontaliere EMESSE per la P.IVA ' + cfcliente)
            r = s.get(f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/ft/emesse/dal/{data_iniziale_trimestre}/al/{data_finale_trimestre}?v=' + unixTime(), headers=headers)
            with open(base_join(base_dir, 'fe_emessetr_' + cfcliente + '.json'), 'wb') as f:
                f.write(r.content)

            dec_dir, raw_dir = mk_paths("Emesse", cfcliente, base_dir)
            ensure_dir(raw_dir); ensure_dir(dec_dir)

            data_tre = r.json()
            n_fatt_te, n_meta_te = 0, 0

            for fattura in data_tre.get('fatture', []):
                fatturaFile = fattura['tipoInvio'] + fattura['idFattura']

                url_fatt = f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fatture/file/{fatturaFile}?tipoFile=FILE_FATTURA&download=1&v=' + unixTime()
                invoice_filename = scarica_file_fattura(s, url_fatt, headers_token, raw_dir)
                if invoice_filename:
                    n_fatt_te += 1
                    url_meta = f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fatture/file/{fatturaFile}?tipoFile=FILE_METADATI&download=1&v=' + unixTime()
                    if salva_file_metadati(s, url_meta, headers_token, raw_dir, invoice_filename):
                        n_meta_te += 1
                        if COPY_META_EMESSE_ALSO_IN_BASE:
                            src = os.path.join(raw_dir, build_metadato_name_from_invoice(invoice_filename))
                            dst = os.path.join(dec_dir, build_metadato_name_from_invoice(invoice_filename))
                            try:
                                shutil.copyfile(src, dst)
                            except Exception as e:
                                print(f"Impossibile copiare metadato in base: {e}")

            decrypt_p7m_files(raw_dir, dec_dir)

            with open(base_join(base_dir, 'output_fatture.txt'), 'a', encoding='utf-8') as file:
                print('TRANSFRONTALIERE EMESSE - fatture:', n_fatt_te, ' metadati:', n_meta_te, file=file)

        if VenOAcq != "V":
            # Transfrontaliere RICEVUTE
            print('Scarico il json delle fatture Transfrontaliere RICEVUTE per la P.IVA ' + cfcliente)
            r = s.get(f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/ft/ricevute/dal/{data_iniziale_trimestre}/al/{data_finale_trimestre}?v=' + unixTime(), headers=headers)
            with open(base_join(base_dir, 'fe_ricevutetr_' + cfcliente + '.json'), 'wb') as f:
                f.write(r.content)

            dec_dir, raw_dir = mk_paths("Ricevute", cfcliente, base_dir)
            ensure_dir(raw_dir); ensure_dir(dec_dir)

            data_tr = r.json()
            n_fatt_tr, n_meta_tr = 0, 0

            for fattura in data_tr.get('fatture', []):
                fatturaFile = fattura['tipoInvio'] + fattura['idFattura']

                url_fatt = f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fatture/file/{fatturaFile}?tipoFile=FILE_FATTURA&download=1&v=' + unixTime()
                invoice_filename = scarica_file_fattura(s, url_fatt, headers_token, raw_dir)
                if invoice_filename:
                    n_fatt_tr += 1

                    url_meta = f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fatture/file/{fatturaFile}?tipoFile=FILE_METADATI&download=1&v=' + unixTime()
                    if salva_file_metadati(s, url_meta, headers_token, dec_dir, invoice_filename):
                        n_meta_tr += 1

            decrypt_p7m_files(raw_dir, dec_dir)

            with open(base_join(base_dir, 'output_fatture.txt'), 'a', encoding='utf-8') as file:
                print('TRANSFRONTALIERE RICEVUTE - fatture:', n_fatt_tr, ' metadati:', n_meta_tr, file=file)

except KeyboardInterrupt:
    print("Programma INTERROTTO manualmente!")
