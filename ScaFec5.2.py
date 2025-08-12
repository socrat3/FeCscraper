## Licenza Libera progetto originario di Claudio Pizzillo
## Modifiche e riadattamenti da Salvatore Crapanzano
## V. 4.3.0 del 12-08-2025  - CLI robusta (cfstudio opzionale), default BASE_DIR=CWD, VERIFY=True, RETRIES=10; SHA-256 + retry + log

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
import hashlib
from clint.textui import colored, puts
from tqdm import tqdm
from typing import Optional, Tuple

# ---------- Config/Flag predefiniti ----------
VERIFY_INTEGRITY = True  # default sempre attiva
MAX_RETRIES = 10         # default 10

# ---------- Utility ----------

def aggiusta_fine_trimestre(d):
    if d.month < 4:
        return datetime(d.year, 3, 31)
    elif d.month < 7:
        return datetime(d.year, 6, 30)
    elif d.month < 10:
        return datetime(d.year, 9, 30)
    else:
        return datetime(d.year, 12, 31)

def divide_in_trimestri(data_iniziale, data_finale):
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

def mk_paths(kind: str, cfcliente: str, base_dir: str):
    dec = base_join(base_dir, f"Fatture{kind}_{cfcliente}")
    raw = dec + "_p7m"
    return dec, raw

def parse_filename_from_cd(cd_value: str) -> Optional[str]:
    if not cd_value:
        return None
    m = re.search(r"filename\*\s*=\s*(?:UTF-8''|utf-8'')?\"?([^\";]+)\"?", cd_value, flags=re.IGNORECASE)
    if not m:
        m = re.search(r'filename\s*=\s*"?([^\";]+)"?', cd_value, flags=re.IGNORECASE)
    return m.group(1) if m else None

def stream_to_file(resp, fullpath, label):
    total_size = int(resp.headers.get('content-length', 0))
    ensure_dir(os.path.dirname(fullpath))
    with open(fullpath, 'wb') as f, tqdm(total=total_size, unit='B', unit_divisor=1024, unit_scale=True, ascii=True) as pbar:
        pbar.set_description(f"Scarico {label}")
        for chunk in resp.iter_content(chunk_size=1024):
            if chunk:
                f.write(chunk)
                pbar.update(len(chunk))

def build_metadato_name_from_invoice(invoice_filename: str) -> str:
    return f"{invoice_filename}_metadato.xml"

def compute_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()

def verify_xml_wellformed(path: str) -> bool:
    try:
        import xml.etree.ElementTree as ET
        ET.parse(path)
        return True
    except Exception as e:
        print(f"XML non valido ({path}): {e}")
        return False

def verify_p7m_with_openssl(path: str) -> bool:
    tmp_out = path + ".verify.tmp"
    cmd = f'openssl cms -decrypt -verify -inform DER -in "{path}" -noverify -out "{tmp_out}"'
    try:
        subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            os.remove(tmp_out)
        except Exception:
            pass
        return True
    except subprocess.CalledProcessError:
        try:
            if os.path.exists(tmp_out):
                os.remove(tmp_out)
        except Exception:
            pass
        return False

def download_with_retries(session, url, headers_token, dest_fullpath, verify_kind: str, label: str, base_dir_logs: str) -> bool:
    ok = False
    part = dest_fullpath + ".part"
    final_sha256 = None

    for attempt in range(1, MAX_RETRIES + 1):
        err_msg = None
        http_status = None
        temp_sha256 = None
        verified = False

        if os.path.exists(part):
            try: os.remove(part)
            except Exception: pass

        try:
            with session.get(url, headers=headers_token, stream=True) as r:
                http_status = r.status_code
                if r.status_code != 200:
                    err_msg = f"HTTP {r.status_code}"
                else:
                    stream_to_file(r, part, f"{label} (tentativo {attempt}/{MAX_RETRIES})")
        except Exception as e:
            err_msg = f"EXC: {e}"

        if http_status == 200 and err_msg is None and os.path.exists(part):
            try:
                temp_sha256 = compute_sha256(part)
            except Exception as e:
                err_msg = f"SHA256_ERR: {e}"

            if err_msg is None and VERIFY_INTEGRITY:
                try:
                    if verify_kind == 'xml':
                        verified = verify_xml_wellformed(part)
                    elif verify_kind == 'p7m':
                        verified = verify_p7m_with_openssl(part)
                    else:
                        verified = True
                except Exception as e:
                    err_msg = f"VERIFY_EXC: {e}"
            else:
                verified = (err_msg is None)

        if err_msg is None and verified:
            try:
                if os.path.exists(dest_fullpath):
                    os.remove(dest_fullpath)
                os.replace(part, dest_fullpath)
                final_sha256 = compute_sha256(dest_fullpath)
                ok = True
            except Exception as e:
                err_msg = f"FINALIZE_ERR: {e}"
                ok = False

        # Log per tentativo
        try:
            ensure_dir(base_dir_logs)
            log_path = os.path.join(base_dir_logs, "download_log.jsonl")
            entry = {
                "ts": datetime.now().isoformat(timespec='seconds'),
                "label": label,
                "url": url,
                "dest": dest_fullpath,
                "attempt": attempt,
                "verify_kind": verify_kind,
                "http_status": http_status,
                "temp_sha256": temp_sha256,
                "verified": verified,
                "finalized": ok,
                "final_sha256": final_sha256 if ok else None,
                "error": err_msg
            }
            with open(log_path, "a", encoding="utf-8") as lf:
                lf.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception as e:
            print(f"Impossibile scrivere il log: {e}")

        if ok:
            break
        else:
            puts(colored.red(f"[{label}] Tentativo {attempt}/{MAX_RETRIES} fallito: {err_msg or 'verifica fallita'}. Riprovo..."))

    if not ok:
        puts(colored.red(f"[{label}] ERRORE: impossibile scaricare/verificare il file dopo {MAX_RETRIES} tentativi."))

    return ok

def decrypt_p7m_files(input_dir, output_dir):
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
        lname = filename.lower()
        if lname.endswith(".p7m"):
            base, _ = os.path.splitext(filename)
            dst = os.path.join(output_dir, base)
            command = f'openssl cms -decrypt -verify -inform DER -in "{src}" -noverify -out "{dst}"'
            print(command)
            try:
                subprocess.run(command, shell=True, check=True)
                print(f"Decriptazione e verifica di {filename} completate con successo.")
            except subprocess.CalledProcessError as e:
                print(f"Errore durante la decriptazione del file {filename}: {e}")
        elif lname.endswith(".xml"):
            shutil.copy(src, os.path.join(output_dir, filename))

# ---------- Download wrappers ----------

def scarica_file_fattura(session, url, headers_token, dest_dir, base_dir_logs) -> Optional[str]:
    with session.get(url, headers=headers_token, stream=True) as r_probe:
        if r_probe.status_code != 200:
            puts(colored.red(f"[fattura] HTTP {r_probe.status_code} in fase di probing."))
            return None
        invoice_filename = parse_filename_from_cd(r_probe.headers.get('content-disposition')) or "fattura_senza_nome.xml"
    dest_fullpath = os.path.join(dest_dir, invoice_filename)
    verify_kind = 'p7m' if invoice_filename.lower().endswith('.p7m') else 'xml'
    ok = download_with_retries(session, url, headers_token, dest_fullpath, verify_kind, f"fattura: {invoice_filename}", base_dir_logs)
    return invoice_filename if ok else None

def salva_file_metadati(session, url, headers_token, dest_dir, invoice_filename: str, base_dir_logs) -> bool:
    renamed_meta_name = build_metadato_name_from_invoice(invoice_filename)
    dest_fullpath = os.path.join(dest_dir, renamed_meta_name)
    return download_with_retries(session, url, headers_token, dest_fullpath, 'xml', f"metadato: {renamed_meta_name}", base_dir_logs)

# ---------- Parsing CLI robusto ----------

def parse_cli(argv):
    """
    Supporta due forme:
    A) con CF_STUDIO:
       1 CF 2 PIN 3 PASS 4 CF_STUDIO 5 DAL 6 AL 7 CF_CLIENTE 8 PIVA 9 TIPO 10 VenOAcq [11 BASE_DIR] [12 VERIFY] [13 RETRIES]
    B) senza CF_STUDIO:
       1 CF 2 PIN 3 PASS 4 DAL 5 AL 6 CF_CLIENTE 7 PIVA 8 TIPO 9 VenOAcq [10 BASE_DIR] [11 VERIFY] [12 RETRIES]
    Defaults: BASE_DIR=CWD, VERIFY=True, RETRIES=10
    """
    if len(argv) < 10:
        print('Uso: script.py CF PIN PASS [CF_STUDIO] DAL(DDMMYYYY) AL(DDMMYYYY) CF_CLIENTE PIVA TIPO(1|2|3) VenOAcq(V|A|T) [BASE_DIR] [VERIFY] [RETRIES]')
        sys.exit(1)

    CF = argv[1]
    PIN = argv[2]
    Password = argv[3]

    # Riconoscimento automatico della forma guardando argv[4]:
    # Se è una data ddmmyyyy → forma B (senza cfstudio)
    has_cfstudio = not bool(re.fullmatch(r'\d{8}', argv[4]))
    idx = 4
    if has_cfstudio:
        cfstudio = argv[idx]; idx += 1
    else:
        cfstudio = ""

    Dal = argv[idx]; idx += 1
    Al = argv[idx]; idx += 1
    cfcliente = argv[idx]; idx += 1
    pivadiretta = argv[idx]; idx += 1
    tipo_str = argv[idx]; idx += 1
    VenOAcq = argv[idx].upper(); idx += 1

    # Opzionali
    base_dir = argv[idx] if len(argv) > idx else os.getcwd(); idx += 1
    verify_arg = argv[idx] if len(argv) > idx else None; idx += 1
    retries_arg = argv[idx] if len(argv) > idx else None; idx += 1

    # Validazioni/Default
    try:
        tipo = int(tipo_str)
        if tipo not in (1,2,3):
            raise ValueError()
    except Exception:
        print(f"Parametro TIPO non valido: '{tipo_str}'. Usa 1=ricezione, 2=emissione, 3=entrambi.")
        sys.exit(1)

    if VenOAcq not in ("V","A","T"):
        print(f"Parametro VenOAcq non valido: '{VenOAcq}'. Usa V=vendite, A=acquisti, T=tutti.")
        sys.exit(1)

    # Defaults robusti
    base_dir = os.path.normpath(base_dir) if base_dir else os.getcwd()

    global VERIFY_INTEGRITY, MAX_RETRIES
    if verify_arg is None:
        VERIFY_INTEGRITY = True
    else:
        VERIFY_INTEGRITY = verify_arg not in ("0", "false", "False", "NO", "No", "no")

    if retries_arg is None:
        MAX_RETRIES = 10
    else:
        try:
            MAX_RETRIES = max(1, int(retries_arg))
        except Exception:
            MAX_RETRIES = 10

    # Info diagnostica
    forma = "A (con CF_STUDIO)" if has_cfstudio else "B (senza CF_STUDIO)"
    puts(colored.yellow(f"Parsing CLI: forma {forma}. BASE_DIR='{base_dir}', VERIFY={VERIFY_INTEGRITY}, RETRIES={MAX_RETRIES}"))

    return CF, PIN, Password, cfstudio, Dal, Al, cfcliente, pivadiretta, tipo, VenOAcq, base_dir

# ---------- Blocco principale ----------

try:
    CF, PIN, Password, cfstudio, Dal, Al, cfcliente, pivadiretta, tipo, VenOAcq, base_dir = parse_cli(sys.argv)

    trimestri = divide_in_trimestri(Dal, Al)
    print(trimestri)

    for data_iniziale_trimestre, data_finale_trimestre in trimestri:
        print(f"Elaborazione del periodo {data_iniziale_trimestre} - {data_finale_trimestre}")

        s = requests.Session()
        s.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.119 Safari/537.36',
            'Connection': 'keep-alive'
        })
        s.cookies.set_cookie(requests.cookies.create_cookie(domain='ivaservizi.agenziaentrate.gov.it', name='LFR_SESSION_STATE_20159', value='expired'))
        s.cookies.set_cookie(requests.cookies.create_cookie(domain='ivaservizi.agenziaentrate.gov.it', name='LFR_SESSION_STATE_10811916', value=unixTime()))

        r = s.get('https://ivaservizi.agenziaentrate.gov.it/portale/web/guest', verify=False)
        if r.status_code == 200:
            puts(colored.yellow('Collegamento alla homepage. Avvio.'))
        else:
            puts(colored.red('Collegamento alla homepage non riuscito: uscita.'))
            sys.exit(1)

        print('Effettuo il login')
        payload = {'_58_saveLastPath': 'false', '_58_redirect' : '', '_58_doActionAfterLogin': 'false', '_58_login': CF , '_58_pin': PIN, '_58_password': Password}    
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

        print('Seleziono il tipo di incarico')
        profilo = 1  # puoi parametrizzare se necessario
        if profilo == 1:
            payload = {'cf_inserito': cfcliente}
            s.post(f'https://ivaservizi.agenziaentrate.gov.it/portale/scelta-utenza-lavoro?p_auth={p_auth}&p_p_id=SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet&p_p_lifecycle=1&p_p_state=normal&p_p_mode=view&p_p_col_id=column-1&p_p_col_count=1&_SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet_javax.portlet.action=delegaDirettaAction', data=payload)
            payload = {'cf_inserito': cfcliente, 'sceltapiva': pivadiretta}
            s.post(f'https://ivaservizi.agenziaentrate.gov.it/portale/scelta-utenza-lavoro?p_auth={p_auth}&p_p_id=SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet&p_p_lifecycle=1&p_p_state=normal&p_p_mode=view&p_p_col_id=column-1&p_p_col_count=1&_SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet_javax.portlet.action=delegaDirettaAction', data=payload)
        # (altri profili omessi per brevità; replicare se necessari)

        print('Aderisco al servizio')
        r = s.get('https://ivaservizi.agenziaentrate.gov.it/ser/api/fatture/v1/ul/me/adesione/stato/')
        if r.status_code == 200:
            puts(colored.yellow('Adesione riuscita ai servizi AdE.'))
        else:
            puts(colored.red('Adesione ai servizi AdE non riuscita: uscita.')) 
            sys.exit(1)

        headers_token = {'x-xss-protection': '1; mode=block', 'strict-transport-security': 'max-age=16070400; includeSubDomains','x-content-type-options': 'nosniff','x-frame-options': 'deny'}
        r = s.get('https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/sc/tokenB2BCookie/get?v='+unixTime(), headers=headers_token)
        if r.status_code != 200:
            puts(colored.red('B2B Cookie non ottenuto: uscita.'))
            sys.exit(1)

        xb2bcookie = r.headers.get('x-b2bcookie')
        xtoken = r.headers.get('x-token')

        s.headers.update({'Host': 'ivaservizi.agenziaentrate.gov.it','Referer': 'https://ivaservizi.agenziaentrate.gov.it/cons/cons-web/?v=' + unixTime(),'Accept': 'application/json, text/plain, */*','Accept-Encoding': 'gzip, deflate, br','Accept-Language': 'it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7,fr;q=0.6','DNT': '1','X-XSS-Protection': '1; mode=block','Strict-Transport-Security': 'max-age=16070400; includeSubDomains','X-Content-Type-Options': 'nosniff','X-Frame-Options': 'deny','x-b2bcookie': xb2bcookie,'x-token': xtoken})
        headers = {'Host': 'ivaservizi.agenziaentrate.gov.it','referer': 'https://ivaservizi.agenziaentrate.gov.it/cons/cons-web/?v=' + unixTime(),'accept': 'application/json, text/plain, */*','accept-encoding': 'gzip, deflate, br','accept-language': 'it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7,fr;q=0.6','DNT': '1','x-xss-protection': '1; mode=block','strict-transport-security': 'max-age=16070400; includeSubDomains','x-content-type-options': 'nosniff','x-frame-options': 'deny','x-b2bcookie': xb2bcookie,'x-token': xtoken,'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.119 Safari/537.36'}

        print('Accetto le condizioni')
        s.get('https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/disclaimer/accetta?v='+unixTime(), headers=headers_token)

        # ================= ACQUISTI (RICEVUTE) =================
        if VenOAcq != "V":
            def scarica_passive(tipo_local):
                print(('Scarico il json RICEVUTE per RICEZIONE' if tipo_local == 1 else 'Scarico il json RICEVUTE per EMISSIONE') + ' per ' + cfcliente)
                if tipo_local == 1:
                    url = f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fe/ricevute/dal/{data_iniziale_trimestre}/al/{data_finale_trimestre}/ricerca/ricezione?v=' + unixTime()
                else:
                    url = f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fe/ricevute/dal/{data_iniziale_trimestre}/al/{data_finale_trimestre}/ricerca/emissione?v=' + unixTime()

                resp = s.get(url, headers=headers)
                with open(base_join(base_dir, f'fe_ricevute_{cfcliente}_tipo{tipo_local}.json'), 'wb') as f:
                    f.write(resp.content)

                puts(colored.red('Inizio a scaricare le PASSIVE per tipo ' + colored.green(str(tipo_local))))
                dec_dir, raw_dir = mk_paths("Ricevute", cfcliente, base_dir)
                ensure_dir(raw_dir); ensure_dir(dec_dir)

                data_j = resp.json()
                n_fatt, n_meta = 0, 0
                for fattura in data_j.get('fatture', []):
                    fatturaFile = fattura['tipoInvio'] + fattura['idFattura']

                    url_fatt = f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fatture/file/{fatturaFile}?tipoFile=FILE_FATTURA&download=1&v=' + unixTime()
                    invoice_filename = scarica_file_fattura(s, url_fatt, headers_token, raw_dir, base_dir)
                    if invoice_filename:
                        n_fatt += 1
                        url_meta = f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fatture/file/{fatturaFile}?tipoFile=FILE_METADATI&download=1&v=' + unixTime()
                        if salva_file_metadati(s, url_meta, headers_token, raw_dir, invoice_filename, base_dir):
                            n_meta += 1

                decrypt_p7m_files(raw_dir, dec_dir)

                with open(base_join(base_dir, 'output_fatture.txt'), 'a', encoding='utf-8') as file:
                    print('Trimestre:', (data_iniziale_trimestre, data_finale_trimestre), file=file)
                    print('PASSIVE RICEVUTE - fatture:', n_fatt, ' metadati:', n_meta, file=file)

            if tipo in (1,3): scarica_passive(1)
            if tipo in (2,3): scarica_passive(2)

        # ================= VENDITE (EMESSE) =================
        if VenOAcq != "A":
            print('Scarico il json EMESSE per la P.IVA ' + cfcliente)
            r = s.get(f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fe/emesse/dal/{data_iniziale_trimestre}/al/{data_finale_trimestre}?v=' + unixTime(), headers=headers)
            with open(base_join(base_dir, 'fe_emesse_' + cfcliente + '.json'), 'wb') as f:
                f.write(r.content)

            dec_dir, raw_dir = mk_paths("Emesse", cfcliente, base_dir)
            ensure_dir(raw_dir); ensure_dir(dec_dir)

            n_fatt_e, n_meta_e = 0, 0
            data_em = r.json()

            for fattura in data_em.get('fatture', []):
                fatturaFile = fattura['tipoInvio'] + fattura['idFattura']

                url_fatt = f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fatture/file/{fatturaFile}?tipoFile=FILE_FATTURA&download=1&v=' + unixTime()
                invoice_filename = scarica_file_fattura(s, url_fatt, headers_token, raw_dir, base_dir)
                if invoice_filename:
                    n_fatt_e += 1
                    url_meta = f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fatture/file/{fatturaFile}?tipoFile=FILE_METADATI&download=1&v=' + unixTime()
                    if salva_file_metadati(s, url_meta, headers_token, raw_dir, invoice_filename, base_dir):
                        n_meta_e += 1

            decrypt_p7m_files(raw_dir, dec_dir)

            with open(base_join(base_dir, 'output_fatture.txt'), 'a', encoding='utf-8') as file:
                print('EMESSE - fatture:', n_fatt_e, ' metadati:', n_meta_e, file=file)

        # ================= TRANSFRONTALIERE =================
        if VenOAcq != "A":
            print('Scarico il json Transfrontaliere EMESSE')
            r = s.get(f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/ft/emesse/dal/{data_iniziale_trimestre}/al/{data_finale_trimestre}?v=' + unixTime(), headers=headers)
            with open(base_join(base_dir, 'fe_emessetr_' + cfcliente + '.json'), 'wb') as f:
                f.write(r.content)

            data_tre = r.json()
            dec_dir, raw_dir = mk_paths("Emesse", cfcliente, base_dir)
            ensure_dir(raw_dir); ensure_dir(dec_dir)

            n_fatt_te, n_meta_te = 0, 0
            for fattura in data_tre.get('fatture', []):
                fatturaFile = fattura['tipoInvio'] + fattura['idFattura']
                url_fatt = f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fatture/file/{fatturaFile}?tipoFile=FILE_FATTURA&download=1&v=' + unixTime()
                invoice_filename = scarica_file_fattura(s, url_fatt, headers_token, raw_dir, base_dir)
                if invoice_filename:
                    n_fatt_te += 1
                    url_meta = f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fatture/file/{fatturaFile}?tipoFile=FILE_METADATI&download=1&v=' + unixTime()
                    if salva_file_metadati(s, url_meta, headers_token, raw_dir, invoice_filename, base_dir):
                        n_meta_te += 1

            decrypt_p7m_files(raw_dir, dec_dir)

            with open(base_join(base_dir, 'output_fatture.txt'), 'a', encoding='utf-8') as file:
                print('TRANSFRONTALIERE EMESSE - fatture:', n_fatt_te, ' metadati:', n_meta_te, file=file)

        if VenOAcq != "V":
            print('Scarico il json Transfrontaliere RICEVUTE')
            r = s.get(f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/ft/ricevute/dal/{data_iniziale_trimestre}/al/{data_finale_trimestre}?v=' + unixTime(), headers=headers)
            with open(base_join(base_dir, 'fe_ricevutetr_' + cfcliente + '.json'), 'wb') as f:
                f.write(r.content)

            data_tr = r.json()
            dec_dir, raw_dir = mk_paths("Ricevute", cfcliente, base_dir)
            ensure_dir(raw_dir); ensure_dir(dec_dir)

            n_fatt_tr, n_meta_tr = 0, 0
            for fattura in data_tr.get('fatture', []):
                fatturaFile = fattura['tipoInvio'] + fattura['idFattura']
                url_fatt = f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fatture/file/{fatturaFile}?tipoFile=FILE_FATTURA&download=1&v=' + unixTime()
                invoice_filename = scarica_file_fattura(s, url_fatt, headers_token, raw_dir, base_dir)
                if invoice_filename:
                    n_fatt_tr += 1
                    url_meta = f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fatture/file/{fatturaFile}?tipoFile=FILE_METADATI&download=1&v=' + unixTime()
                    if salva_file_metadati(s, url_meta, headers_token, raw_dir, invoice_filename, base_dir):
                        n_meta_tr += 1

            decrypt_p7m_files(raw_dir, dec_dir)

            with open(base_join(base_dir, 'output_fatture.txt'), 'a', encoding='utf-8') as file:
                print('TRANSFRONTALIERE RICEVUTE - fatture:', n_fatt_tr, ' metadati:', n_meta_tr, file=file)

        # ================= MESSE A DISPOSIZIONE =================
        if VenOAcq != "V":
            print('Scarico il json MESSE A DISPOSIZIONE')
            r = s.get(f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fe/mc/dal/{data_iniziale_trimestre}/al/{data_finale_trimestre}?v=' + unixTime(), headers=headers)
            with open(base_join(base_dir, 'fe_ricevute_disposizione_' + cfcliente + '.json'), 'wb') as f:
                f.write(r.content)

            dec_dir, raw_dir = mk_paths("Ricevute", cfcliente, base_dir)
            ensure_dir(raw_dir); ensure_dir(dec_dir)

            numero_fatture_disposizione = 0
            data_mc = r.json()
            for fattura in data_mc.get('fatture', []):
                fatturaFile = fattura['tipoInvio'] + fattura['idFattura']
                url_fatt = f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fatture/file/{fatturaFile}?tipoFile=FILE_FATTURA&download=1&v=' + unixTime()
                # probing + download con retry
                inv_name_probe = None
                with s.get(url_fatt, headers=headers_token, stream=True) as r_probe:
                    if r_probe.status_code == 200:
                        inv_name_probe = parse_filename_from_cd(r_probe.headers.get('content-disposition')) or "fattura_senza_nome.xml"
                if inv_name_probe is None:
                    continue
                verify_kind = 'p7m' if inv_name_probe.lower().endswith('.p7m') else 'xml'
                dest_fullpath = os.path.join(raw_dir, inv_name_probe)
                if download_with_retries(s, url_fatt, headers_token, dest_fullpath, verify_kind, f"fattura (MC): {inv_name_probe}", base_dir):
                    numero_fatture_disposizione += 1

            decrypt_p7m_files(raw_dir, dec_dir)

            with open(base_join(base_dir, 'output_fatture.txt'), 'a', encoding='utf-8') as file:
                print('MESSE A DISPOSIZIONE - fatture:', numero_fatture_disposizione, file=file)

except KeyboardInterrupt:
    print("Programma INTERROTTO manualmente!")
