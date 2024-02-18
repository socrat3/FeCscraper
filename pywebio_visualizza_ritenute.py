## Vers. 0.1 del 18-02-2024 che mostra una tabella con le fatture ricevute che contengono ritenute
## sotto GPL v. 3 di Salvatore Crapanzano
## si deve usare con altro script elabora_ritenute.py
from pywebio.input import input, FLOAT, input_group  # Corretta l'importazione
from pywebio.output import put_row, put_text, put_buttons, put_table, popup, toast, close_popup

from pywebio import start_server
import sqlite3
db_path = 'C:\scarica\invoices.db'
def fetch_and_display_data():
    db_path = 'C:\scarica\invoices.db'
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM invoices")
    rows = cursor.fetchall()

    headers = ['ID', 'Cedente P.IVA', 'Cedente', 'Cessionario P.IVA', 'Cessionario', 'Nr Fattura', 'Data Fattura', 'Ritenuta', 'Importo Ritenuta', 'Ritenuta %', 'Azioni']
    
    # Converti tutti i dati in stringhe, specialmente i valori booleani
    table_data = []
    for row in rows:
        formatted_row = [str(item) for item in row]
        action_buttons = put_buttons(['aggiorna', 'cancella'], onclick=[lambda x=row[0]: update_record(x), lambda x=row[0]: delete_record(x)])
        formatted_row.append(action_buttons)
        table_data.append(formatted_row)
    
    # Visualizza i dati nella tabella
    put_table([headers] + table_data)
    
    conn.close()

def update_record(record_id):
    def process_update(data):
        # Qui dentro inserisci la logica per aggiornare il database con i nuovi dati
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("UPDATE invoices SET cedente_piva=?, importo_ritenuta=? WHERE id=?", (data['cedente_piva'], data['importo_ritenuta'], record_id))
        conn.commit()
        cursor.close()
        conn.close()
        toast('Record aggiornato con successo')
        fetch_and_display_data()
        close_popup()

    popup('Aggiorna Record', content=[
        input_group("Inserisci nuovi valori", [
            input('Cedente P.IVA', name='cedente_piva'),
            input('Importo Ritenuta', name='importo_ritenuta', type=FLOAT),
        ], validate=process_update)
    ])

def delete_record(record_id):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM invoices WHERE id=?", (record_id,))
    conn.commit()
    cursor.close()
    conn.close()
    toast(f'Record {record_id} eliminato con successo')
    fetch_and_display_data()

if __name__ == '__main__':
    start_server(fetch_and_display_data, port=8080)
