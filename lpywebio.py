# gestione fatture elettroniche di Salvatore Crapanzano
# 0.1 del11/02/2024
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

# Crea una tabella (se non esiste già)
c.execute('''CREATE TABLE IF NOT EXISTS records
             (id INTEGER PRIMARY KEY, name TEXT, age INTEGER)''')
conn.commit()

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
    """Visualizza tutti i record nel database."""
    c.execute("SELECT * FROM records")
    records = c.fetchall()
    clear()
    for id, name, age in records:
        put_text(f"ID: {id}, Nome: {name}, Età: {age}")
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
    """Elimina un record dopo conferma."""
    id = input("Inserisci l'ID del record da eliminare", type=NUMBER)
    
    # Chiedi conferma prima di procedere con l'eliminazione
    confirm = actions('Confermi di voler eliminare il record?', ['Sì', 'No'])
    if confirm == 'Sì':
        c.execute("DELETE FROM records WHERE id = ?", (id,))
        conn.commit()
        toast('Record eliminato con successo!')
    else:
        toast('Eliminazione annullata.')
        
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
    """Mostra il menu principale."""
    clear()
    put_buttons(['Aggiungi Record', 'Visualizza Record', 'Aggiorna Record', 'Elimina Record', 'Esporta in PDF'], onclick=[add_record, view_records, update_record, delete_record, export_records_to_pdf])

if __name__ == '__main__':
    start_server(main_menu, port=8888, debug=True)
