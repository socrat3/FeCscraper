# gestione fatture elettroniche di Salvatore Crapanzano
# 0.3 del11/02/2024
from pywebio.input import *
from pywebio.output import *
from pywebio import start_server
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import os
import sqlite3


# Connettiti al database SQLite
conn = sqlite3.connect('example.db', check_same_thread=False)
c = conn.cursor()

def main_menu():
    """Mostra il menu principale e visualizza la tabella dei record."""
    clear()
    put_buttons(['Aggiungi Record', 'Visualizza Record', 'Aggiorna Record', 'Elimina Record', 'Esporta in PDF', 'Imposta Visualizzazione Record'], onclick=[add_record, lambda: fetch_and_display_records(50), update_record, delete_record, export_records_to_pdf, set_records_view])
    fetch_and_display_records()

def fetch_and_display_records(limit=50, offset=0):
    """Fetch records from the database and display them in a table, with pagination."""
    if limit == 'tutti':
        c.execute("SELECT * FROM records")
    else:
        c.execute("SELECT * FROM records LIMIT ? OFFSET ?", (limit, offset))
    records = c.fetchall()

    # Clears only the table area, not the entire page
    clear('records_table')

    if records:
        # Display records in a table
        table_data = [['ID', 'Nome', 'Età']] + [[str(record[0]), record[1], str(record[2])] for record in records]
        put_table(table_data, scope='records_table')
    else:
        put_text("Nessun record trovato.", scope='records_table')
def set_records_view():

    """Allows the user to set how many records to view."""
    limit = input("Inserisci il numero di record da visualizzare per pagina o 'tutti' per visualizzare tutti i record", type=TEXT)
    if limit.isdigit():
        limit = int(limit)
    elif limit != 'tutti':
        toast('Per favore, inserisci un numero valido o "tutti"', color='error')
        return
    fetch_and_display_records(limit)

def change_page(direction, limit, current_offset):
    """Change the page of records displayed."""
    new_offset = max(0, current_offset + direction)
    fetch_and_display_records(limit, new_offset)

# Implementa qui le funzioni add_record, update_record, delete_record, export_records_to_pdf



def add_record():
    """Aggiungi un nuovo record al database."""
    data = input_group("Aggiungi Record", [
        input('Inserisci nome', name='name'),
        input('Inserisci età', name='age', type=NUMBER),
    ])
    c.execute("INSERT INTO records (name, age) VALUES (?, ?)", (data['name'], data['age']))
    conn.commit()
    toast('Record aggiunto con successo!')

def view_records():
    """Visualizza i record nel database con un limite configurabile."""
    limit = input("Inserisci il numero di record da visualizzare o 'tutti' per mostrare tutti i record", type=TEXT)
    
    if limit.isdigit():
        limit = int(limit)
        sql_query = "SELECT * FROM records LIMIT ?"
        params = (limit,)
    else:
        sql_query = "SELECT * FROM records"
        params = ()

    c.execute(sql_query, params)
    records = c.fetchall()
    
    clear()

    if records:
        # Costruisce l'intestazione della tabella e i dati
        header = ['ID', 'Nome', 'Età']
        data = [[str(record[0]), record[1], str(record[2])] for record in records]
        put_table([header] + data)
    else:
        put_text("Nessun record trovato.")

    put_buttons(['Indietro'], onclick=[main_menu])

def update_record():
    """Aggiorna un record esistente."""
    id = input("Inserisci l'ID del record da aggiornare", type=NUMBER)
    data = input_group("Aggiorna Record", [
        input('Nuovo nome', name='name'),
        input('Nuova età', name='age', type=NUMBER),
    ])
    c.execute("UPDATE records SET name = ?, age = ? WHERE id = ?", (data['name'], data['age'], id))
    conn.commit()
    toast('Record aggiornato con successo!')

def delete_record():
    """Elimina un record dopo conferma, mostrando ID e nome."""
    id = input("Inserisci l'ID del record da eliminare", type=NUMBER)
    
    # Recupera il nome del record da eliminare per mostrarlo nel messaggio di conferma
    c.execute("SELECT name FROM records WHERE id = ?", (id,))
    result = c.fetchone()
    
    if result:
        name = result[0]
        # Chiedi conferma mostrando ID e nome
        confirm = actions(f'Confermi di voler eliminare il record con ID {id} e nome "{name}"?', ['Sì', 'No'])
        if confirm == 'Sì':
            c.execute("DELETE FROM records WHERE id = ?", (id,))
            conn.commit()
            toast('Record eliminato con successo!')
        else:
            toast('Eliminazione annullata.')
    else:
        toast("Fattura non non trovata. Riprova!")
        
def export_records_to_pdf():
    """Esporta tutti i record in un file PDF."""
    c.execute("SELECT * FROM records")
    records = c.fetchall()

    if not records:
        toast("Nessun record da esportare.", duration=2)
        return

    # Configura il documento PDF
    filename = "records.pdf"
    pdf_canvas = canvas.Canvas(filename, pagesize=letter)  # Modifica qui per evitare conflitti di nome
    width, height = letter
    pdf_canvas.drawString(100, height - 100, "Record del Database")

    # Aggiungi i record al PDF
    y = height - 125
    for id, name, age in records:
        line = f"ID: {id}, Nome: {name}, Età: {age}"
        pdf_canvas.drawString(100, y, line)
        y -= 25

    pdf_canvas.save()
    toast("Record esportati in PDF con successo!", duration=2)

    # Offri all'utente la possibilità di scaricare il file PDF
    put_file(filename, os.path.getsize(filename), 'Scarica PDF')

def main_menu():
    """Mostra il menu principale e visualizza sempre la tabella dei record sotto."""
    clear()
    put_buttons(['Aggiungi Record', 'Visualizza Record', 'Aggiorna Record', 'Elimina Record', 'Esporta in PDF', 'Imposta Visualizzazione Record'], onclick=[add_record, lambda: fetch_and_display_records(50), update_record, delete_record, export_records_to_pdf, set_records_view])
    # Scope dedicato per la tabella dei record
    put_scope('records_table')
    # Chiamata iniziale per popolare la tabella con i primi 50 record
    fetch_and_display_records()
    
if __name__ == '__main__':
    start_server(main_menu, port=8888, debug=True)