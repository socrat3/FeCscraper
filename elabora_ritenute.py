## Vers. 0.1 del 18-02-2024 che mostra una tabella con le fatture ricevute che contengono ritenute
## sotto GPL v. 3 di Salvatore Crapanzano
## si deve usare con altro script pywebio_elabora_ritenute_corretto.py e delle fatture xml inserito in dati

import xml.etree.ElementTree as ET
import sqlite3
import os

def extract_complete_data(xml_path):
    tree = ET.parse(xml_path)
    root = tree.getroot()
    
    cedente_piva = root.find('.//CedentePrestatore/DatiAnagrafici/IdFiscaleIVA/IdCodice').text
    cedente_denominazione = root.find('.//CedentePrestatore/DatiAnagrafici/Anagrafica/Cognome').text
    cessionario_piva = root.find('.//CessionarioCommittente/DatiAnagrafici/IdFiscaleIVA/IdCodice').text
    cessionario_denominazione = root.find('.//CessionarioCommittente/DatiAnagrafici/Anagrafica/Cognome').text
    
    numero_fattura = root.find('.//FatturaElettronicaBody/DatiGenerali/DatiGeneraliDocumento/Numero').text
    data_fattura = root.find('.//FatturaElettronicaBody/DatiGenerali/DatiGeneraliDocumento/Data').text
    
    ritenuta_element = root.find('.//FatturaElettronicaBody/DatiGenerali/DatiGeneraliDocumento/DatiRitenuta/ImportoRitenuta')
    ritenuta = ritenuta_element is not None
    importo_ritenuta = ritenuta_element.text if ritenuta else None
    aliquota_ritenuta = root.find('.//FatturaElettronicaBody/DatiGenerali/DatiGeneraliDocumento/DatiRitenuta/AliquotaRitenuta').text if ritenuta else None

    return {
        'cedente_piva': cedente_piva,
        'cedente_denominazione': cedente_denominazione,
        'cessionario_piva': cessionario_piva,
        'cessionario_denominazione': cessionario_denominazione,
        'numero_fattura': numero_fattura,
        'data_fattura': data_fattura,
        'ritenuta': ritenuta,
        'importo_ritenuta': importo_ritenuta,
        'aliquota_ritenuta': aliquota_ritenuta
    }

def save_to_database(data, db_connection):
    cursor = db_connection.cursor()
    # Verifica se il numero della fattura esiste già
    cursor.execute('SELECT id FROM invoices WHERE numero_fattura = ?', (data['numero_fattura'],))
    exists = cursor.fetchone()
    if not exists:
        cursor.execute('''
            INSERT INTO invoices (
                cedente_piva, cedente_denominazione, cessionario_piva, cessionario_denominazione, 
                numero_fattura, data_fattura, ritenuta, importo_ritenuta, aliquota_ritenuta
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            data['cedente_piva'],
            data['cedente_denominazione'],
            data['cessionario_piva'],
            data['cessionario_denominazione'],
            data['numero_fattura'],
            data['data_fattura'],
            data['ritenuta'],
            data['importo_ritenuta'],
            data['aliquota_ritenuta']
        ))
        db_connection.commit()
    else:
        print(f"Fattura {data['numero_fattura']} esistente. Inserimento ignorato.")

# Impostazione dei percorsi per il database e la cartella contenente i file XML
db_path = 'C:\\scarica\\invoices.db'
folder_path = 'C:\\scarica\\dati'

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

cursor.execute('''
    CREATE TABLE IF NOT EXISTS invoices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cedente_piva TEXT,
        cedente_denominazione TEXT,
        cessionario_piva TEXT,
        cessionario_denominazione TEXT,
        numero_fattura TEXT UNIQUE,
        data_fattura TEXT,
        ritenuta BOOLEAN,
        importo_ritenuta TEXT,
        aliquota_ritenuta TEXT
    )
''')

# Processo tutti i file XML nella cartella specificata
for file in os.listdir(folder_path):
    if file.endswith(".xml"):
        xml_file_path = os.path.join(folder_path, file)
        data = extract_complete_data(xml_file_path)
        save_to_database(data, conn)

conn.close()  # Chiudi la connessione al database quando hai finito
