#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ScaFec 6.0 - 14/08/2025
Downloader Fatture AdE con tabella live, JSON di periodo e verifiche robuste
Origine: progetto Pizzillo | Modifiche: S. Crapanzano | Hardening v6.0

Novità v6.0:
- Richiesta date (DAL/AL) solo se non specificate in CLI o nel file JSON
- Supporto completo CLI posizionale: CF PIN PASS DAL AL CF_CLIENTE PIVA TIPO V|A|T BASE_DIR VERIFY RETRIES
- Forzatura skip via CLI: --skip-existing / --no-skip-existing (priorità su JSON)
- Conferma runtime di VERIFY_INTEGRITY / MAX_RETRIES / SKIP_EXISTING
- Tabella “Ultimi file”: File | Azione | Verificato(OK/KO)
"""

import os, sys, re, io, json, base64, shutil, platform, subprocess, hashlib
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, Any, List
import requests
import pytz
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# opzionali
try:
    from asn1crypto import cms as _cms_int
except Exception:
    _cms_int = None
try:
    import win32crypt as _win32crypt_int  # Windows-only
except Exception:
    _win32crypt_int = None

# UI opzionale (fallback se mancante)
_HAVE_RICH = True
try:
    from rich.live import Live
    from rich.table import Table
    from rich.panel import Panel
    from rich.console import Console
    from rich import box
except Exception:
    _HAVE_RICH = False

# tqdm e messaggi color
try:
    from tqdm import tqdm
except Exception:
    tqdm = None
try:
    from clint.textui import colored, puts
except Exception:
    class _Dummy:
        def __getattr__(self, x): return lambda s: s
    colored = _Dummy()
    def puts(s): print(s)

# ---------- Costanti / default ----------
VERIFY_INTEGRITY = True
MAX_RETRIES = 10
SKIP_EXISTING = True
DEFAULT_CONFIG_FILE = "config_ade_system.json"
REQUEST_TIMEOUT = 30  # secondi (overridable via --timeout o JSON rete.timeout)

def _print_help():
    print("""
ScaFec 6.0 - 14/08/2025 | Guida rapida (IT)

USO BASE
  python ScaFec6.0.py --config config_ade_system.json
  (Se 'periodo.dal' e/o 'periodo.al' non sono nel file o sono vuoti, verranno richiesti a video.)

USO FALLBACK SOLO CLI (forma posizionale)
  python ScaFec6.0.py CF PIN PASS DAL AL CF_CLIENTE PIVA TIPO V|A|T BASE_DIR VERIFY RETRIES
  Esempio:
  python ScaFec6.0.py T2495292 674C29B1 KUTRAYW8 01012025 31082025 VZZGPP81A21A089F 02327190845 3 T C:\\SCARICA\\cartella_di_lavoro 1 3

OPZIONI CLI
  --config <file>          Percorso al file di configurazione JSON (default: config_ade_system.json se presente)
  --skip-existing          Non sovrascrivere i file già presenti (priorità sul JSON)
  --no-skip-existing       Sovrascrivere i file anche se già presenti (priorità sul JSON)
  --verbose                Abilita log estesi (URL, HTTP status, percorsi JSON)
  --no-live                Disattiva la UI dinamica rich.Live (usa soli log testuali)
  --proxy <url>            Imposta proxy esplicito per HTTP/HTTPS (es. http://user:pass@host:port)
  --no-proxy               Disabilita l'uso del proxy (ignora variabili d'ambiente)
  --timeout <secondi>      Timeout per le richieste HTTP (default 30)
  --trust-env              Consenti a requests di usare variabili d'ambiente (HTTP(S)_PROXY)
  --no-trust-env           Impedisci l'uso delle variabili d'ambiente
  --help                   Mostra questo aiuto
  --no-live               Disattiva la visualizzazione dinamica (usa log testuali), utile per debug
  --verbose               Log estesi (URL, HTTP status, percorsi JSON)
  --proxy <url>           Forza proxy (es. http://user:pass@host:port). Sovrascrive JSON e variabili d'ambiente
  --no-proxy              Disattiva proxy (ignora JSON e ambiente)
  --timeout <sec>         Timeout richieste HTTP (default 30)
  --trust-env             Abilita uso di variabili d'ambiente per proxy/certificati
  --no-trust-env          Disabilita uso delle variabili d'ambiente per proxy/certificati

SIGNIFICATO OPZIONI CHIAVE (Italiano)
  periodo.dal / periodo.al
    Intervallo di date in formato DDMMYYYY (es. 01012025). Se mancanti, saranno richieste all'esecuzione.
  periodo.tipo
    1 = ricezione, 2 = emissione, 3 = entrambi
  periodo.vena
    V = vendite (emesse), A = acquisti (ricevute), T = tutti
  configurazione_download.skip_existing (true/false)
    true  = NON sovrascrivere file già presenti (ma se VERIFY_INTEGRITY=true, verifica la validità)
    false = Sovrascrivi sempre i file scaricandoli di nuovo
  verify (true/false)
    Abilita la verifica di integrità (XML ben formato / P7M con OpenSSL se disponibile)
  retries (int >= 1)
    Numero massimo di tentativi per ciascun download

NOTE
  - I JSON "di periodo" vengono salvati prima di ogni altro step e includono DAL/AL nel nome.
  - La tabella a video mostra: stato per cliente e “Ultimi file” (File | Azione | Verificato).
""")
    return

# ---------- Utility di base ----------
def unixTime():
    dt = datetime.now(tz=pytz.utc)
    return str(int(dt.timestamp() * 1000))

def ensure_dir(p: str):
    os.makedirs(p, exist_ok=True)

def base_join(base_dir: str, *parts: str) -> str:
    return os.path.normpath(os.path.join(base_dir, *parts))

def aggiusta_fine_trimestre(d):
    if d.month < 4: return datetime(d.year, 3, 31)
    elif d.month < 7: return datetime(d.year, 6, 30)
    elif d.month < 10: return datetime(d.year, 9, 30)
    else: return datetime(d.year, 12, 31)

def divide_in_trimestri(data_iniziale: str, data_finale: str):
    d1 = datetime.strptime(data_iniziale, "%d%m%Y")
    d2 = datetime.strptime(data_finale, "%d%m%Y")
    trimestri = []
    while d1 <= d2:
        fine = aggiusta_fine_trimestre(d1)
        if fine >= d2:
            trimestri.append((d1.strftime("%d%m%Y"), d2.strftime("%d%m%Y"))); break
        else:
            trimestri.append((d1.strftime("%d%m%Y"), fine.strftime("%d%m%Y")))
        d1 = fine + timedelta(days=1)
    return trimestri

def mk_paths(kind: str, cfcliente: str, base_dir: str):
    dec = base_join(base_dir, f"Fatture{kind}_{cfcliente}")
    raw = dec + "_p7m"
    return dec, raw

def parse_filename_from_cd(cd_value: str) -> Optional[str]:
    if not cd_value: return None
    m = re.search(r"filename\*\s*=\s*(?:UTF-8''|utf-8'')?\"?([^\";]+)\"?", cd_value, flags=re.IGNORECASE)
    if not m:
        m = re.search(r'filename\s*=\s*"?([^\";]+)"?', cd_value, flags=re.IGNORECASE)
    return m.group(1) if m else None

def compute_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1024*1024), b''):
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

def _openssl_in_path() -> bool:
    try:
        res = subprocess.run(["openssl", "version"], capture_output=True, text=True, timeout=5)
        return res.returncode == 0
    except Exception:
        return False

def verify_p7m_with_openssl(path: str) -> bool:
    if not _openssl_in_path():
        print("Attenzione: 'openssl' non rilevato nel PATH; salto la verifica P7M via OpenSSL.")
        return True
    tmp_out = path + ".verify.tmp"
    cmd = ["openssl","cms","-decrypt","-verify","-inform","DER","-in",path,"-noverify","-out",tmp_out]
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try: os.remove(tmp_out)
        except Exception: pass
        return True
    except subprocess.CalledProcessError:
        try:
            if os.path.exists(tmp_out): os.remove(tmp_out)
        except Exception: pass
        return False

def _is_base64_encoded(content: bytes) -> bool:
    if content.startswith(b'<?xml') or content.startswith(b'\x30\x82'):
        return False
    try:
        cleaned = b"".join(content.split())
        decoded = base64.b64decode(cleaned, validate=True)
        return len(decoded) > 0
    except Exception:
        return False

def _robust_preprocess_base64(file_path: str):
    try:
        with open(file_path, 'rb') as f:
            original = f.read()
        if not _is_base64_encoded(original):
            return file_path, False
        cleaned = b"".join(original.split())
        decoded = base64.b64decode(cleaned)
        import tempfile
        tf = tempfile.NamedTemporaryFile(delete=False, suffix=".p7m")
        tf.write(decoded); tf.close()
        return tf.name, True
    except Exception:
        return file_path, False

def _extract_with_asn1(p7m_path: str):
    if _cms_int is None: return None
    try:
        with open(p7m_path, 'rb') as f: p7m_data = f.read()
        ci = _cms_int.ContentInfo.load(p7m_data)
        sd = ci.get('content');  eci = sd.get('encap_content_info') if sd else None
        content = eci.get('content') if eci else None
        if not content: return None
        econtent = content.native
        if isinstance(econtent, (bytes, bytearray)):
            try: return econtent.decode('utf-8')
            except UnicodeDecodeError: return econtent.decode('utf-8', errors='ignore')
    except Exception:
        return None
    return None

def _extract_with_winapi(p7m_path: str):
    if platform.system() != "Windows" or _win32crypt_int is None: return None
    try:
        with open(p7m_path, 'rb') as f: p7m_data = f.read()
        decoded_tuple = _win32crypt_int.CryptDecodeMessage(
            _win32crypt_int.PKCS_7_ASN_ENCODING | _win32crypt_int.X509_ASN_ENCODING,
            None, _win32crypt_int.CMSG_SIGNED, p7m_data, len(p7m_data)
        )
        if decoded_tuple and decoded_tuple[0]:
            try: return decoded_tuple[0].decode('utf-8')
            except UnicodeDecodeError: return decoded_tuple[0].decode('utf-8', errors='ignore')
    except Exception:
        return None
    return None

def _extract_with_openssl(p7m_path: str):
    if not _openssl_in_path(): return None
    for fmt in ('DER','PEM'):
        try:
            res = subprocess.run(['openssl','cms','-verify','-noverify','-inform',fmt,'-in',p7m_path],
                                 capture_output=True, text=True, encoding='utf-8', errors='ignore', timeout=30)
            if res.returncode == 0 and res.stdout:
                out = res.stdout; i = out.find('<?xml')
                if i != -1: return out[i:]
        except Exception:
            continue
    return None

def _extract_bruteforce(p7m_path: str):
    try:
        with open(p7m_path, 'rb') as f: content = f.read()
        for enc in ('utf-8','latin-1','cp1252'):
            try: s = content.decode(enc, errors='ignore')
            except Exception: continue
            m = re.search(r'(<\?xml.*?</.*?:?FatturaElettronica>)', s, re.DOTALL|re.IGNORECASE)
            if m: return m.group(1)
            start = s.find('<?xml')
            if start != -1:
                endings = ('</p:FatturaElettronica>','</FatturaElettronica>','</ns2:FatturaElettronica>','</ns:FatturaElettronica>')
                for e in endings:
                    j = s.find(e, start)
                    if j != -1: return s[start:j+len(e)]
    except Exception:
        return None
    return None

def _decode_single_p7m_to_xml(src_path: str) -> Optional[str]:
    p, is_temp = _robust_preprocess_base64(src_path)
    xml = None
    try:
        for fn in (_extract_with_asn1, _extract_with_winapi, _extract_with_openssl, _extract_bruteforce):
            try: xml = fn(p)
            except Exception: xml = None
            if xml: break
    finally:
        if is_temp:
            try: os.remove(p)
            except Exception: pass
    return xml

# ---------- UI Live Table ----------
class ProgressUI:
    def __init__(self, use_rich: bool = _HAVE_RICH, console_log: bool = True):
        self.use_rich = use_rich
        self._live = None
        self.rows: Dict[str, Dict[str, int]] = {}  # client_key -> dict(stats)
        self.console_log = console_log
        if self.use_rich:
            self.console = Console()
        else:
            self.console = None
        self._log_lines: List[str] = []
        self._last_files: List[Dict[str, str]] = []  # each: {file, azione, verificato}

    def init_client(self, client_name: str):
        if client_name not in self.rows:
            self.rows[client_name] = {"tot": 0, "done": 0}

    def set_total(self, client_name: str, total: int):
        self.init_client(client_name)
        self.rows[client_name]["tot"] = total

    def inc_done(self, client_name: str, n: int = 1):
        self.init_client(client_name)
        self.rows[client_name]["done"] += n
        if self.rows[client_name]["done"] > self.rows[client_name]["tot"]:
            self.rows[client_name]["done"] = self.rows[client_name]["tot"]

    def add_file(self, file_name: str, azione: str, verificato_ok: bool):
        status = "OK" if verificato_ok else "KO"
        self._last_files.append({"file": file_name or "(sconosciuto)", "azione": azione, "verificato": status})
        if len(self._last_files) > 10:
            self._last_files = self._last_files[-10:]

    def log(self, line: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self._log_lines.append(f"[{ts}] {line}")
        if len(self._log_lines) > 10:
            self._log_lines = self._log_lines[-10:]
        # refresh immediato se logging su console attivo
        if self.console_log:
            self.update()

    def _render_rich(self):
        table = Table(title="Scarico Fatture - Stato per Cliente", box=box.SIMPLE_HEAVY)
        table.add_column("Cliente", style="bold")
        table.add_column("Totale")
        table.add_column("Scaricate")
        table.add_column("Residue")
        for name, st in self.rows.items():
            tot = st["tot"]; done = st["done"]; res = max(tot - done, 0)
            table.add_row(name, str(tot), str(done), str(res))

        files_table = Table(title="Ultimi file", box=box.SIMPLE)
        files_table.add_column("File")
        files_table.add_column("Azione")
        files_table.add_column("Verificato")
        for row in self._last_files:
            files_table.add_row(row["file"], row["azione"], row["verificato"])

        log_panel = Panel("\n".join(self._log_lines) or "Log in corso...", title="Attività", box=box.SIMPLE)
        layout = Table.grid(expand=True)
        layout.add_row(table)
        layout.add_row(files_table)
        layout.add_row(log_panel)
        return layout

    def bind(self, live):
        self._live = live

    def live(self):
        if not self.use_rich:
            class _DummyLive:
                def __enter__(self_): return self
                def __exit__(self_, exc_type, exc, tb): return False
                def update(self_, *_a, **_k): pass
            return _DummyLive()
        else:
            return Live(self._render_rich(), console=self.console, refresh_per_second=10)

    def update(self):
        if self.use_rich:
            if self._live is not None:
                self._live.update(self._render_rich())
            return
        else:
            # Fallback testuale
            os.system('cls' if os.name == 'nt' else 'clear')
            print("Scarico Fatture - Stato per Cliente")
            print("-"*60)
            for name, st in self.rows.items():
                tot = st["tot"]; done = st["done"]; res = max(tot - done, 0)
                print(f"{name:30}  Tot:{tot:5d}  Done:{done:5d}  Res:{res:5d}")
            print("-"*60)
            print("Ultimi file (File | Azione | Verificato)")
            for row in self._last_files[-10:]:
                print(f"{row['file']} | {row['azione']} | {row['verificato']}")
            print("-"*60)
            for line in self._log_lines:
                print(line)

# ---------- Download helpers ----------
def stream_to_file(resp, fullpath, label):
    total_size = int(resp.headers.get('content-length', 0))
    ensure_dir(os.path.dirname(fullpath))
    if tqdm:
        with open(fullpath, 'wb') as f, tqdm(total=total_size, unit='B', unit_divisor=1024, unit_scale=True, ascii=True) as pbar:
            pbar.set_description(f"{label}")
            for chunk in resp.iter_content(chunk_size=1024):
                if chunk:
                    f.write(chunk); pbar.update(len(chunk))
    else:
        with open(fullpath, 'wb') as f:
            for chunk in resp.iter_content(chunk_size=1024):
                if chunk: f.write(chunk)

def download_with_retries(session, url, headers_token, dest_fullpath, verify_kind: str, label: str, base_dir_logs: str):
    ok = False
    part = dest_fullpath + ".part"
    final_sha256 = None
    verified = False

    # skip existing
    if SKIP_EXISTING and os.path.exists(dest_fullpath):
        verified_here = True
        try:
            if VERIFY_INTEGRITY:
                if verify_kind == 'xml': verified_here = verify_xml_wellformed(dest_fullpath)
                elif verify_kind == 'p7m': verified_here = verify_p7m_with_openssl(dest_fullpath)
                else: verified_here = True
            else:
                verified_here = True
        except Exception:
            verified_here = False
        if verified_here:
            return {"ok": True, "verified": True, "skipped": True, "final_sha256": compute_sha256(dest_fullpath)}
        # se non verificato -> si prosegue con il download per rigenerarlo

    for attempt in range(1, MAX_RETRIES + 1):
        err_msg = None; http_status = None; temp_sha256 = None; verified = False
        if os.path.exists(part):
            try: os.remove(part)
            except Exception: pass

        try:
            with session.get(url, headers=headers_token, stream=True) as r:
                http_status = r.status_code
                if r.status_code != 200:
                    err_msg = f"HTTP {r.status_code}"
                else:
                    stream_to_file(r, part, f"{label} (try {attempt}/{MAX_RETRIES})")
        except Exception as e:
            err_msg = f"EXC: {e}"

        if http_status == 200 and err_msg is None and os.path.exists(part):
            try:
                temp_sha256 = compute_sha256(part)
            except Exception as e:
                err_msg = f"SHA256_ERR: {e}"

            if err_msg is None and VERIFY_INTEGRITY:
                try:
                    if verify_kind == 'xml': verified = verify_xml_wellformed(part)
                    elif verify_kind == 'p7m': verified = verify_p7m_with_openssl(part)
                    else: verified = True
                except Exception as e:
                    err_msg = f"VERIFY_EXC: {e}"
            else:
                verified = (err_msg is None)

        if err_msg is None and verified:
            try:
                if os.path.exists(dest_fullpath): os.remove(dest_fullpath)
                os.replace(part, dest_fullpath)
                final_sha256 = compute_sha256(dest_fullpath); ok = True
            except Exception as e:
                err_msg = f"FINALIZE_ERR: {e}"; ok = False

        # Log per tentativo
        try:
            ensure_dir(base_dir_logs)
            log_path = os.path.join(base_dir_logs, "download_log.jsonl")
            entry = {
                "ts": datetime.now().isoformat(timespec='seconds'),
                "label": label, "url": url, "dest": dest_fullpath,
                "attempt": attempt, "verify_kind": verify_kind,
                "http_status": http_status, "verified": verified,
                "finalized": ok, "final_sha256": final_sha256 if ok else None,
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
        puts(colored.red(f"[{label}] ERRORE: impossibile scaricare/verificare dopo {MAX_RETRIES} tentativi."))

    return {"ok": ok, "verified": bool(verified), "skipped": False, "final_sha256": final_sha256}

def scarica_file_fattura(session, url, headers_token, dest_dir, base_dir_logs, ui: ProgressUI, client_key: str, filename_hint: Optional[str]=None) -> Optional[str]:
    # probing per ottenere il nome file
    inv_name = None
    with session.get(url, headers=headers_token, stream=True) as r_probe:
        if r_probe.status_code == 200:
            inv_name = parse_filename_from_cd(r_probe.headers.get('content-disposition')) or filename_hint or "fattura_senza_nome.xml"
    if inv_name is None:
        return None
    verify_kind = 'p7m' if inv_name.lower().endswith('.p7m') else 'xml'
    dest_fullpath = os.path.join(dest_dir, inv_name)
    res = download_with_retries(session, url, headers_token, dest_fullpath, verify_kind, f"fattura: {inv_name}", base_dir_logs)
    if res:
        if res.get("skipped"):
            ui.add_file(inv_name, "saltato (presente)", res.get("verified", False))
        elif res.get("ok"):
            ui.add_file(inv_name, "scaricato", res.get("verified", True))
        if res.get("ok"):
            ui.inc_done(client_key, 1)
        return inv_name if res.get("ok") else None
    return None

def salva_file_metadati(session, url, headers_token, dest_dir, invoice_filename: str, base_dir_logs) -> bool:
    renamed_meta_name = f"{invoice_filename}_metadato.xml"
    dest_fullpath = os.path.join(dest_dir, renamed_meta_name)
    res = download_with_retries(session, url, headers_token, dest_fullpath, 'xml', f"metadato: {renamed_meta_name}", base_dir_logs)
    return bool(res and res.get('ok'))

def decrypt_p7m_files(input_dir, output_dir):
    if not os.path.exists(input_dir) or not os.path.isdir(input_dir):
        print(f"Directory input {input_dir} assente o non directory."); return
    os.makedirs(output_dir, exist_ok=True)
    entries = os.listdir(input_dir)
    if not entries:
        print(f"Nessun file in {input_dir}."); return

    for filename in entries:
        src = os.path.join(input_dir, filename); lname = filename.lower()
        if lname.endswith(".p7m"):
            base, _ = os.path.splitext(filename)
            dest = os.path.join(output_dir, base)
            try:
                xml = _decode_single_p7m_to_xml(src)
                if xml:
                    if not dest.lower().endswith(".xml"): dest += ".xml"
                    with open(dest, "w", encoding="utf-8") as f: f.write(xml)
                    print(f"Decodifica OK: {filename} -> {os.path.basename(dest)}")
                else:
                    print(f"Decodifica FALLITA per: {filename}")
            except Exception as e:
                print(f"Errore in decodifica {filename}: {e}")
        elif lname.endswith(".xml"):
            try: shutil.copy(src, os.path.join(output_dir, filename))
            except Exception as e: print(f"Errore copia XML {filename}: {e}")

# ---------- Config / CLI ----------
def _get_cli_flag(argv: List[str], flag: str) -> bool:
    return flag in argv

def _extract_cli_value(argv: List[str], flag: str) -> Optional[str]:
    if flag in argv:
        try:
            i = argv.index(flag)
            return argv[i+1]
        except Exception:
            return None
    return None

def _is_valid_date_str(s: Optional[str]) -> bool:
    return bool(s and re.fullmatch(r"\d{8}", s))

def load_config(argv: List[str]) -> Dict[str, Any]:
    """
    Priorità: --config <file> -> DEFAULT_CONFIG_FILE se esiste -> fallback CLI (forma posizionale).
    CLI forma posizionale: CF PIN PASS DAL AL CF_CLIENTE PIVA TIPO(1|2|3) V|A|T BASE_DIR VERIFY RETRIES
    Flags extra:
      --skip-existing / --no-skip-existing  (priorità su JSON)
    """
    cfg_path = _extract_cli_value(argv, "--config")
    if not cfg_path and os.path.exists(DEFAULT_CONFIG_FILE):
        cfg_path = DEFAULT_CONFIG_FILE

    skip_flag = None
    if _get_cli_flag(argv, "--skip-existing"):
        skip_flag = True
    if _get_cli_flag(argv, "--no-skip-existing"):
        skip_flag = False
    verbose_flag = _get_cli_flag(argv, "--verbose")
    no_live_flag = _get_cli_flag(argv, "--no-live")
    no_proxy_flag = _get_cli_flag(argv, "--no-proxy")
    trust_env_flag = _get_cli_flag(argv, "--trust-env")
    no_trust_env_flag = _get_cli_flag(argv, "--no-trust-env")
    proxy_value = _extract_cli_value(argv, "--proxy")
    timeout_value = _extract_cli_value(argv, "--timeout")
    no_proxy_flag = _get_cli_flag(argv, "--no-proxy")
    trust_env_flag = _get_cli_flag(argv, "--trust-env")
    no_trust_env_flag = _get_cli_flag(argv, "--no-trust-env")
    proxy_value = _extract_cli_value(argv, "--proxy")
    timeout_value = _extract_cli_value(argv, "--timeout")

    if cfg_path and os.path.exists(cfg_path):
        with open(cfg_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        if skip_flag is not None:
            cfg.setdefault("configurazione_download", {})["skip_existing"] = skip_flag
        if verbose_flag:
            cfg["verbose"] = True
        if no_live_flag:
            cfg["no_live"] = True
        # rete overrides
        rete = cfg.setdefault("rete", {})
        if proxy_value:
            rete["None"] = proxy_value; rete["None"] = proxy_value
        if no_proxy_flag:
            rete["None"] = ""; rete["None"] = ""; rete["use_system_proxy"] = False
        if timeout_value and str(timeout_value).isdigit():
            rete["timeout"] = int(timeout_value)
        if trust_env_flag:
            rete["trust_env"] = True
        if no_trust_env_flag:
            rete["trust_env"] = False
        return cfg

    # Fallback CLI posizionale
    if len(argv) < 13:
        print('Uso (CLI): script.py CF PIN PASS DAL(DDMMYYYY) AL(DDMMYYYY) CF_CLIENTE PIVA TIPO(1|2|3) V|A|T BASE_DIR VERIFY RETRIES')
        sys.exit(1)

    CF, PIN, Password = argv[1], argv[2], argv[3]
    Dal, Al, cfcliente, pivadiretta, tipo_str, VenOAcq = argv[4], argv[5], argv[6], argv[7], argv[8], argv[9].upper()
    base_dir = argv[10]
    verify_arg = argv[11]
    retries_arg = argv[12]

    try:
        tipo = int(tipo_str)
        assert tipo in (1,2,3)
    except Exception:
        print("TIPO non valido: usa 1=ricezione, 2=emissione, 3=entrambi."); sys.exit(1)
    if VenOAcq not in ("V","A","T"):
        print("VenOAcq non valido: V/A/T"); sys.exit(1)

    cfg = {
        "credenziali_ade": {
            "codice_fiscale": CF, "pin": PIN, "password": Password, "codice_fiscale_studio": ""
        },
        "portfolio_clienti": {
            "cliente_cli": {
                "nome_azienda": cfcliente, "partita_iva_diretta": pivadiretta, "codice_fiscale": cfcliente,
                "profilo_accesso": 1, "attivo": True
            }
        },
        "configurazione_download": {
            "tipi_documenti": {
                "fatture_emesse": True, "fatture_ricevute": True,
                "transfrontaliere_emesse": True, "transfrontaliere_ricevute": True
            },
            "download_metadati": True, "decodifica_p7m": True, "pausa_tra_download": 0.0,
            "skip_existing": True,
        },
        "directory_sistema": {
            "input_temp": "temp_download_ade",
            "output_base": base_dir,
            "archivio": "archivio_input",
            "logs": "logs_sistema",
            "reports": "reports_sistema"
        },
        "periodo": {"dal": Dal, "al": Al, "tipo": int(tipo), "vena": VenOAcq},
        "verify": (verify_arg not in ("0","false","False","no","No")),
        "retries": max(1, int(retries_arg)) if str(retries_arg).isdigit() else 10,
        "logging": {"livello": "INFO", "file_log": True, "console_log": True},
        "verbose": verbose_flag,
        "no_live": no_live_flag,
        "rete": {
            "None": proxy_value or "",
            "None": proxy_value or "",
            "timeout": int(timeout_value) if (timeout_value and str(timeout_value).isdigit()) else REQUEST_TIMEOUT,
            "use_system_proxy": (False if no_proxy_flag else True),
            "trust_env": (False if no_trust_env_flag else True)
        }
    }
    if skip_flag is not None:
        cfg["configurazione_download"]["skip_existing"] = skip_flag
    # CLI overrides for proxy/trust_env
    if proxy_value is not None:
        cfg["rete"]["None"] = proxy_value
        cfg["rete"]["None"] = proxy_value
        cfg["rete"]["use_system_proxy"] = False
    if no_proxy_flag:
        cfg["rete"]["None"] = ""; cfg["rete"]["None"] = ""; cfg["rete"]["use_system_proxy"] = False
    if trust_env_flag:
        cfg["rete"]["trust_env"] = True
    if no_trust_env_flag:
        cfg["rete"]["trust_env"] = False
    return cfg

# ---------- Blocco principale ----------
def main():
    global VERIFY_INTEGRITY, MAX_RETRIES, SKIP_EXISTING
    if '--help' in sys.argv:
        _print_help(); return
    cfg = load_config(sys.argv)

    # rete / timeout
    rete = cfg.get("rete", {})
    timeout_sec = int(rete.get("timeout", REQUEST_TIMEOUT))
    proxies = {}
    if rete.get("None"): proxies["http"] = rete.get("None")
    if rete.get("None"): proxies["https"] = rete.get("None")
    use_system_proxy = bool(rete.get("use_system_proxy", True))
    trust_env = bool(rete.get("trust_env", True))


    # parametri generali
    creds = cfg.get("credenziali_ade", {})
    CF = creds.get("codice_fiscale", "")
    PIN = creds.get("pin", "")
    Password = creds.get("password", "")
    cfstudio = creds.get("codice_fiscale_studio", "")

    # periodo: richiedi SOLO se mancano o sono vuoti/invalidi
    period = cfg.get("periodo", {})
    Dal = str(period.get("dal", "")).strip()
    Al  = str(period.get("al", "")).strip()
    tipo = int(period.get("tipo", 3))
    VenOAcq = str(period.get("vena", "T")).upper()

    if not _is_valid_date_str(Dal):
        Dal = input("Inserire DAL (formato DDMMYYYY): ").strip()
        if not _is_valid_date_str(Dal):
            print("Data DAL non valida."); sys.exit(1)
    if not _is_valid_date_str(Al):
        Al = input("Inserire AL  (formato DDMMYYYY): ").strip()
        if not _is_valid_date_str(Al):
            print("Data AL non valida."); sys.exit(1)

    # opzioni
    VERIFY_INTEGRITY = bool(cfg.get("verify", True))
    MAX_RETRIES = int(cfg.get("retries", 10))
    cd = cfg.get("configurazione_download", {})
    SKIP_EXISTING = bool(cd.get("skip_existing", True))

    dirs = cfg.get("directory_sistema", {})
    base_dir = os.path.normpath(dirs.get("output_base", os.getcwd()))
    logs_dir = base_join(base_dir, dirs.get("logs", "logs_sistema"))
    reports_dir = base_join(base_dir, dirs.get("reports", "reports_sistema"))
    ensure_dir(base_dir); ensure_dir(logs_dir); ensure_dir(reports_dir)

    # UI
    # logging console attivo?
    logging_cfg = cfg.get("logging", {})
    console_log_on = bool(logging_cfg.get("console_log", True))
    verbose_on = bool(cfg.get("verbose", False))
    no_live = bool(cfg.get("no_live", False))
    ui = ProgressUI(use_rich=(False if no_live else _HAVE_RICH), console_log=console_log_on)
    live_ctx = ui.live()
    with live_ctx as _live:
        ui.bind(_live)
        # Conferma runtime settaggi
        ui.log(f"VERIFY_INTEGRITY={VERIFY_INTEGRITY}, MAX_RETRIES={MAX_RETRIES}")
        ui.log(f"SKIP_EXISTING={SKIP_EXISTING}")

        # Sessione HTTP e login una volta per tutti i clienti (per trimestre)
        trimestri = divide_in_trimestri(Dal, Al)

        json_paths_summary = []
        for data_iniziale_trimestre, data_finale_trimestre in trimestri:
            # Setup sessione
            s = requests.Session()
            # trust_env consente a requests di leggere proxy/certs da ambiente
            s.trust_env = trust_env
            # Applica proxy se specificati
            proxies = {}
            if proxies:
                proxies["http"] = None
            if proxies:
                proxies["https"] = None
            if proxies and not use_system_proxy:
                s.proxies.update(proxies)
            if verbose_on:
                ui.log(f"Proxy attivi: {s.proxies if s.proxies else 'nessuno'} | trust_env={s.trust_env} | timeout={REQUEST_TIMEOUT}s")

            # Preflight: DNS + TCP connect verso host AdE
            try:
                import socket
                host = 'ivaservizi.agenziaentrate.gov.it'
                ip = socket.gethostbyname(host)
                if verbose_on: ui.log(f"DNS {host} -> {ip}")
                with socket.create_connection((ip, 443), timeout=REQUEST_TIMEOUT):
                    if verbose_on: ui.log(f"TCP connect 443 su {ip} OK")
            except Exception as e:
                ui.log(f"[ERRORE] Preflight rete fallito: {e}")
                print("Impossibile raggiungere il dominio dell'Agenzia: controllare DNS/Firewall/VPN o configurare il proxy con --proxy.")
                return
            s.trust_env = trust_env
            if not use_system_proxy:
                s.trust_env = False
            if proxies:
                s.proxies.update(proxies)
            s.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.119 Safari/537.36',
                'Connection': 'keep-alive'
            })
            s.cookies.set_cookie(requests.cookies.create_cookie(domain='ivaservizi.agenziaentrate.gov.it', name='LFR_SESSION_STATE_20159', value='expired'))
            s.cookies.set_cookie(requests.cookies.create_cookie(domain='ivaservizi.agenziaentrate.gov.it', name='LFR_SESSION_STATE_10811916', value=unixTime()))

            url_home = 'https://ivaservizi.agenziaentrate.gov.it/portale/web/guest'
            if verbose_on:
                ui.log(f"Resolving ivaservizi.agenziaentrate.gov.it ...")
                try:
                    import socket
                    addrs = socket.getaddrinfo('ivaservizi.agenziaentrate.gov.it', 443)
                    ui.log(f"DNS -> {[a[4][0] for a in addrs]}")
                    ui.log("TCP connect 443 ...")
                    sock = socket.create_connection(('ivaservizi.agenziaentrate.gov.it', 443), timeout=timeout_sec)
                    sock.close(); ui.log("TCP OK")
                except Exception as e:
                    ui.log(f"[ERRORE] DNS/TCP: {e}")
            if verbose_on: ui.log(f"GET {url_home}")
            try:
                r = s.get(url_home, verify=False, timeout=timeout_sec)
                if verbose_on: ui.log(f"HTTP {r.status_code} {url_home}")
            except Exception as e:
                ui.log(f"[ERRORE] GET {url_home} fallita: {e}")
                print("Connessione non riuscita all'homepage AdE. Verificare rete/VPN/firewall/DNS/proxy.")
                return
            if r.status_code != 200:
                ui.log("Homepage non raggiunta. Uscita."); sys.exit(1)
            ui.log("Homepage OK. Login in corso...")

            payload = {'_58_saveLastPath': 'false', '_58_redirect' : '', '_58_doActionAfterLogin': 'false', '_58_login': CF , '_58_pin': PIN, '_58_password': Password}
            url_login = 'https://ivaservizi.agenziaentrate.gov.it/portale/home?p_p_id=58&p_p_lifecycle=1&p_p_state=normal&p_p_mode=view&p_p_col_id=column-1&p_p_col_pos=3&p_p_col_count=4&_58_struts_action=%2Flogin%2Flogin'
            if verbose_on: ui.log(f"POST {url_login}")
            try:
                r = s.post(url_login, data=payload, timeout=timeout_sec)
                if verbose_on: ui.log(f"HTTP {r.status_code} {url_login}")
            except Exception as e:
                ui.log(f"[ERRORE] POST {url_login} fallita: {e}")
                print("Login non riuscito: problema di rete o blocco firewall.")
                return

            liferay_m = re.search(r"Liferay\.authToken = '([^']+)';", r.text)
            if not liferay_m:
                ui.log("Token Liferay non trovato. Uscita."); sys.exit(1)
            p_auth = liferay_m.group(1)

            url_api = 'https://ivaservizi.agenziaentrate.gov.it/dp/api?v=' + unixTime()
            if verbose_on: ui.log(f"GET {url_api}")
            try:
                r = s.get(url_api, timeout=timeout_sec)
                if verbose_on: ui.log(f"HTTP {r.status_code} {url_api}")
            except Exception as e:
                ui.log(f"[ERRORE] GET {url_api} fallita: {e}")
                print("API non raggiungibile: rete o sessione.")
                return
            if r.status_code != 200:
                ui.log("Login non riuscito. Uscita."); sys.exit(1)
            ui.log("Login OK (ENTRATEL).")

            headers_token = {'x-xss-protection':'1; mode=block','strict-transport-security':'max-age=16070400; includeSubDomains','x-content-type-options':'nosniff','x-frame-options':'deny'}
            url_token = 'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/sc/tokenB2BCookie/get?v=' + unixTime()
            if verbose_on: ui.log(f"GET {url_token}")
            try:
                r = s.get(url_token, headers=headers_token, timeout=timeout_sec)
                if verbose_on: ui.log(f"HTTP {r.status_code} {url_token}")
            except Exception as e:
                ui.log(f"[ERRORE] GET {url_token} fallita: {e}")
                print("Token B2B non ottenuto: rete o blocco di sicurezza.")
                return
            if r.status_code != 200:
                ui.log("B2B Cookie non ottenuto. Uscita."); sys.exit(1)
            xb2bcookie = r.headers.get('x-b2bcookie'); xtoken = r.headers.get('x-token')

            s.headers.update({
                'Host':'ivaservizi.agenziaentrate.gov.it','Referer':'https://ivaservizi.agenziaentrate.gov.it/cons/cons-web/?v=' + unixTime(),
                'Accept':'application/json, text/plain, */*','Accept-Encoding':'gzip, deflate, br','Accept-Language':'it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7,fr;q=0.6',
                'DNT':'1','X-XSS-Protection':'1; mode=block','Strict-Transport-Security':'max-age=16070400; includeSubDomains',
                'X-Content-Type-Options':'nosniff','X-Frame-Options':'deny','x-b2bcookie': xb2bcookie,'x-token': xtoken
            })
            headers = {
                'Host':'ivaservizi.agenziaentrate.gov.it','referer':'https://ivaservizi.agenziaentrate.gov.it/cons/cons-web/?v=' + unixTime(),
                'accept':'application/json, text/plain, */*','accept-encoding':'gzip, deflate, br','accept-language':'it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7,fr;q=0.6',
                'DNT':'1','x-xss-protection':'1; mode=block','strict-transport-security':'max-age=16070400; includeSubDomains','x-content-type-options':'nosniff',
                'x-frame-options':'deny','x-b2bcookie': xb2bcookie,'x-token': xtoken,'User-Agent': s.headers['User-Agent']
            }

            url_disclaimer = 'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/disclaimer/accetta?v=' + unixTime()
            if verbose_on: ui.log(f"GET {url_disclaimer}")
            try:
                s.get(url_disclaimer, headers=headers_token, timeout=timeout_sec)
            except Exception as e:
                ui.log(f"[ERRORE] GET {url_disclaimer} fallita: {e}")
                print("Disclaimer non accettato: rete o sessione invalida.")
                return

            ui.log(f"Periodo {data_iniziale_trimestre}-{data_finale_trimestre}: avvio per clienti attivi.")

            # Portfolio clienti
            portfolio = {k:v for k,v in cfg.get("portfolio_clienti", {}).items() if v.get("attivo", True)}

            # Per ogni cliente:
            for key, cliente in portfolio.items():
                nome_az = cliente.get("nome_azienda", key)
                cfcliente = cliente.get("codice_fiscale", "")
                pivadiretta = cliente.get("partita_iva_diretta", "")
                profilo = int(cliente.get("profilo_accesso", 1))

                client_key = f"{nome_az}"
                ui.init_client(client_key)
                ui.log(f"[{nome_az}] Selezione utenza...")

                # Selezione utenza cliente (delega diretta), come v5.3
                if profilo == 1:
                    try:
                        payload = {'cf_inserito': cfcliente}
                        s.post(f'https://ivaservizi.agenziaentrate.gov.it/portale/scelta-utenza-lavoro?p_auth={p_auth}&p_p_id=SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet&p_p_lifecycle=1&p_p_state=normal&p_p_mode=view&p_p_col_id=column-1&p_p_col_count=1&_SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet_javax.portlet.action=delegaDirettaAction', data=payload, timeout=(15, timeout_sec))
                        payload = {'cf_inserito': cfcliente, 'sceltapiva': pivadiretta}
                        s.post(f'https://ivaservizi.agenziaentrate.gov.it/portale/scelta-utenza-lavoro?p_auth={p_auth}&p_p_id=SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet&p_p_lifecycle=1&p_p_state=normal&p_p_mode=view&p_p_col_id=column-1&p_p_col_count=1&_SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet_javax.portlet.action=delegaDirettaAction', data=payload, timeout=(15, timeout_sec))
                    except Exception as e:
                        ui.log(f"[ERRORE] Scelta utenza fallita per {nome_az}: {e}")
                        continue

                # --- Prima operazione: scarico JSON di periodo (nomi con DAL/AL) ---
                cd = cfg.get("configurazione_download", {})
                tipos = cd.get("tipi_documenti", {})
                path_json_base = base_dir
                ensure_dir(path_json_base)

                def _save_json_period(name_prefix: str, url: str):
                    if verbose_on:
                        ui.log(f"GET {url}")
                    fname = f"{name_prefix}_{cfcliente}_{data_iniziale_trimestre}_{data_finale_trimestre}.json"
                    full = base_join(path_json_base, fname)
                    try:
                        r = s.get(url, headers=headers, timeout=timeout_sec)
                    except Exception as e:
                        ui.log(f"[ERRORE] GET {url} fallita: {e}")
                        return {}, 0, full
                    try:
                        with open(full, 'wb') as f:
                            f.write(r.content)
                        parsed = {}
                        try:
                            parsed = r.json()
                        except Exception:
                            ui.log(f"[WARN] JSON non parseable per {name_prefix} (HTTP {r.status_code}). File salvato: {os.path.abspath(full)}")
                        else:
                            cnt = len(parsed.get('fatture', [])) if isinstance(parsed, dict) else 0
                            path_abs = os.path.abspath(full)
                            ui.log(f"Salvato JSON: {path_abs} | HTTP {r.status_code} | fatture={cnt}")
                            json_paths_summary.append(path_abs)
                        return parsed, r.status_code, full
                    except Exception as e:
                        ui.log(f"[ERRORE] Salvataggio JSON {name_prefix} fallito: {e}")
                        return {}, 0, full

                tot_previste = 0
                ui.log(f"[{nome_az}] Download JSON di periodo...")

                data_ricevute = {}
                data_emesse = {}
                data_tr_emesse = {}
                data_tr_ricevute = {}
                data_mc = {}
                http_statuses = []

                if tipos.get("fatture_ricevute", True) and VenOAcq != "V":
                    if tipo in (1,3):
                        url = f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fe/ricevute/dal/{data_iniziale_trimestre}/al/{data_finale_trimestre}/ricerca/ricezione?v=' + unixTime()
                        data_ricevute, st1, p1 = _save_json_period("fe_ricevute_ricezione", url); http_statuses.append(st1)
                    if tipo in (2,3):
                        url = f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fe/ricevute/dal/{data_iniziale_trimestre}/al/{data_finale_trimestre}/ricerca/emissione?v=' + unixTime()
                        dr2, st2, p2 = _save_json_period("fe_ricevute_emissione", url); http_statuses.append(st2)
                        if data_ricevute:
                            data_ricevute.setdefault("fatture", [])
                            data_ricevute["fatture"].extend(dr2.get("fatture", []))
                        else:
                            data_ricevute = dr2

                if tipos.get("fatture_emesse", True) and VenOAcq != "A":
                    url = f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fe/emesse/dal/{data_iniziale_trimestre}/al/{data_finale_trimestre}?v=' + unixTime()
                    data_emesse, st3, p3 = _save_json_period("fe_emesse", url); http_statuses.append(st3)

                if tipos.get("transfrontaliere_emesse", True) and VenOAcq != "A":
                    url = f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/ft/emesse/dal/{data_iniziale_trimestre}/al/{data_finale_trimestre}?v=' + unixTime()
                    data_tr_emesse, st4, p4 = _save_json_period("fe_emesse_tr", url); http_statuses.append(st4)

                if tipos.get("transfrontaliere_ricevute", True) and VenOAcq != "V":
                    url = f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/ft/ricevute/dal/{data_iniziale_trimestre}/al/{data_finale_trimestre}?v=' + unixTime()
                    data_tr_ricevute, st5, p5 = _save_json_period("fe_ricevute_tr", url); http_statuses.append(st5)

                if VenOAcq != "V":
                    url = f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fe/mc/dal/{data_iniziale_trimestre}/al/{data_finale_trimestre}?v=' + unixTime()
                    data_mc, st6, p6 = _save_json_period("fe_ricevute_disposizione", url); http_statuses.append(st6)

                for block in (data_ricevute, data_emesse, data_tr_emesse, data_tr_ricevute, data_mc):
                    if isinstance(block, dict): tot_previste += len(block.get("fatture", []))
                ui.set_total(client_key, tot_previste)
                if tot_previste == 0:
                    ui.log(f"[ATTENZIONE] Nessuna fattura rilevata per {nome_az} nel periodo {data_iniziale_trimestre}-{data_finale_trimestre}. Verifica filtri/utenza/permessi.")
                ui.log(f"[{nome_az}] Totale fatture previste nel periodo: {tot_previste} | HTTPs: {','.join(str(x) for x in http_statuses if x)}")
                ui.update()

                # --- Raw/dec destinazioni ---
                dec_r, raw_r = mk_paths("Ricevute", cfcliente, base_dir)
                dec_e, raw_e = mk_paths("Emesse", cfcliente, base_dir)
                ensure_dir(raw_r); ensure_dir(dec_r); ensure_dir(raw_e); ensure_dir(dec_e)

                # --- Download file a partire dai JSON ---
                def _dl_block(data_block: Dict[str,Any], raw_dir: str, label_prefix: str):
                    for fattura in data_block.get('fatture', []):
                        fatturaFile = fattura['tipoInvio'] + fattura['idFattura']
                        url_fatt = f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fatture/file/{fatturaFile}?tipoFile=FILE_FATTURA&download=1&v=' + unixTime()
                        invname = scarica_file_fattura(s, url_fatt, headers_token, raw_dir, logs_dir, ui, client_key)
                        ui.log(f"[{nome_az}] File: {invname or '(nome non rilevato)'}")
                        if invname and cd.get("download_metadati", True):
                            url_meta = f'https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fatture/file/{fatturaFile}?tipoFile=FILE_METADATI&download=1&v=' + unixTime()
                            salva_file_metadati(s, url_meta, headers_token, raw_dir, invname, logs_dir)
                        ui.update()

                if data_ricevute and VenOAcq != "V":
                    _dl_block(data_ricevute, raw_r, "RICEVUTE")
                if data_mc and VenOAcq != "V":
                    _dl_block(data_mc, raw_r, "MESSE A DISPOSIZIONE")
                if data_tr_ricevute and VenOAcq != "V":
                    _dl_block(data_tr_ricevute, raw_r, "TR RICEVUTE")
                if data_emesse and VenOAcq != "A":
                    _dl_block(data_emesse, raw_e, "EMESSE")
                if data_tr_emesse and VenOAcq != "A":
                    _dl_block(data_tr_emesse, raw_e, "TR EMESSE")

                # Decodifica P7M -> dec
                if cd.get("decodifica_p7m", True):
                    decrypt_p7m_files(raw_r, dec_r)
                    decrypt_p7m_files(raw_e, dec_e)

                # report sintetico
                with open(base_join(reports_dir, f"report_{cfcliente}_{data_iniziale_trimestre}_{data_finale_trimestre}.txt"), "a", encoding="utf-8") as rpt:
                    rpt.write(f"{datetime.now().isoformat(timespec='seconds')} - Cliente {nome_az} ({cfcliente}) periodo {data_iniziale_trimestre}-{data_finale_trimestre}\n")
                    done = ui.rows[client_key]['done']
                    rpt.write(f"Totale previste: {tot_previste} - Scaricate: {done} - Residue: {max(0, tot_previste - done)}\n\n")

                ui.log(f"[{nome_az}] Completato periodo {data_iniziale_trimestre}-{data_finale_trimestre}")

    print("Workflow completato.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Interrotto dall'utente.")
