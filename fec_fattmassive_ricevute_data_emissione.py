## Crapanzano Salvatore (Fatture Massive Fattura)
## Per effettuare l'invio delle richieste Fatture Massive sul portale ivaservizi.agenziaentrate.gov.it, inserire il nome del file nella relativa parte del codice
## Vers. 1.9.0 del 31-03-2023
## Cartella di lavoro è ./inviomassivo sotto la dir di lancio dello script di invio
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import re
import sys
import pytz
import json
import os
import base64
import time
from datetime import timedelta, datetime, tzinfo, timezone
from dateutil.parser import parse

def unixTime():
    dt = datetime.now(tz=pytz.utc)
    return str(int(dt.timestamp() * 1000))

def validadata(date_text):
    try:
        datetime.datetime.strptime(date_text, '%Y-%m-%d')
    except ValueError:
        raise ValueError("Date inserite con formato errato! Deve essere AAAA-MM-GG")
        sys.exit(0)

print('ATTENZIONE: Verranno inviate le richieste Fatture Massive con estenzione xml contenute nella sotto-cartella ./inviomassivo')
print('per il cliente impostato nel percorso di lancio del programma!')
now = datetime.now() # corrente date and time
profilo = 1
CF = sys.argv[1]
PIN = sys.argv[2]
Password  = sys.argv[3]
cfstudio = sys.argv[4]
datainiziorichiestacorrispettivi = sys.argv[5]
datafinerichiestacorrispettivi = sys.argv[6]
cfcliente = sys.argv[7]
pivadiretta  = sys.argv[8]
path = r'inviomassivo'

nr_file = 0 
if not os.path.exists(path):
    os.makedirs(path)

# controllo se la data viene passata nel formato corretto AAAA-MM-GG
parse(datainiziorichiestacorrispettivi)
parse(datafinerichiestacorrispettivi)



# Controllo se la data fine è successiva alla data inizio
new_datainiziorichiestacorrispettivi = time.strptime(datainiziorichiestacorrispettivi, '%Y-%m-%d')
new_datafinerichiestacorrispettivi = time.strptime(datafinerichiestacorrispettivi, '%Y-%m-%d')

if (new_datainiziorichiestacorrispettivi > new_datafinerichiestacorrispettivi):
    print("Errore: La data di inizio scaricamento non è precedente la data fine!")
    sys.exit(0)

print("La data di inizio è ", datainiziorichiestacorrispettivi, " mentre la data di fine è ", datafinerichiestacorrispettivi)

# time.sleep(10)

file_corrispettivi = [
'<?xml version="1.0" encoding="UTF-8"?>',
'<ns1:InputMassivo',
'\txsi:schemaLocation="http://www.sogei.it/InputPubblico',
'\tuntitled.xsd"',
'\txmlns:ns1="http://www.sogei.it/InputPubblico"',
'\txmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">',
'\t<ns1:TipoRichiesta>',
'\t\t<ns1:Fatture>',
'\t\t\t<ns1:Richiesta>FATT</ns1:Richiesta>',
'\t\t\t<ns1:ElencoPiva>',
'\t\t\t\t<ns1:Piva>' + pivadiretta + '</ns1:Piva>',
'\t\t\t</ns1:ElencoPiva>',
'\t\t\t<ns1:TipoRicerca>COMPLETA</ns1:TipoRicerca>',
'\t\t\t<ns1:FattureRicevute>',
'\t\t\t\t<ns1:DataEmissione>',
'\t\t\t\t\t<ns1:Da>' + datainiziorichiestacorrispettivi + '</ns1:Da>',
'\t\t\t\t\t<ns1:A>' + datafinerichiestacorrispettivi + '</ns1:A>',
'\t\t\t\t</ns1:DataEmissione>',
'\t\t\t\t<ns1:Flusso><ns1:Tutte>ALL</ns1:Tutte></ns1:Flusso>',
'\t\t\t\t<ns1:Ruolo>CESSIONARIO</ns1:Ruolo>',
'\t\t\t</ns1:FattureRicevute>',
'\t\t</ns1:Fatture>',
'\t</ns1:TipoRichiesta>',
'</ns1:InputMassivo>',
]
# print(file_corrispettivi)

def FileCorrispettivi_scrivi(filename, lines, debug_len=False):
    payload_len, file_len = 0, 0
    with open(filename,'w') as f:
        import os
        print("Creazione del file fatture emesse \"%s\"....."%filename)
        for line in lines:
            payload_len += len(line) + len(os.linesep)
            file_len += f.write(line+'\n')
    if debug_len:
        print("File length:  precomp_payload=%d\tI/O=%d"%(payload_len,file_len))
        sys.exit(0)
cfclientexml = path + '/' + 'FATT_M_RICEVUTE_EMISSIONE' + cfcliente + '.xml'
cfclientexmlnopath = 'FATT_M_RICEVUTE_EMISSIONE' + cfcliente + '.xml' 

#uso della funzione che crea il file con il definizione del nome file xml e ontenuto
FileCorrispettivi_scrivi(cfclientexml, file_corrispettivi)

s = requests.Session()
s.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.119 Safari/537.36'})
s.headers.update({'Connection': 'keep-alive'})

cookie_obj1 = requests.cookies.create_cookie(domain='ivaservizi.agenziaentrate.gov.it',name='LFR_SESSION_STATE_20159',value='expired')
s.cookies.set_cookie(cookie_obj1)
cookie_obj2 = requests.cookies.create_cookie(domain='ivaservizi.agenziaentrate.gov.it',name='LFR_SESSION_STATE_10811916',value=unixTime())
s.cookies.set_cookie(cookie_obj2)
r = s.get('https://ivaservizi.agenziaentrate.gov.it/portale/web/guest', verify=False)

print('Collegamento alla homepage')
cookieJar = s.cookies

print('Effettuo il login')
payload = {'_58_saveLastPath': 'false', '_58_redirect' : '', '_58_doActionAfterLogin': 'false', '_58_login': CF , '_58_pin': PIN, '_58_password': Password}    
r = s.post('https://ivaservizi.agenziaentrate.gov.it/portale/home?p_p_id=58&p_p_lifecycle=1&p_p_state=normal&p_p_mode=view&p_p_col_id=column-1&p_p_col_pos=3&p_p_col_count=4&_58_struts_action=%2Flogin%2Flogin', data=payload)
cookieJar = s.cookies

liferay = re.findall(r"Liferay.authToken = '.*';", r.text)[0]
p_auth = liferay.replace("Liferay.authToken = '","")
p_auth = p_auth.replace("';", "")

r = s.get('https://ivaservizi.agenziaentrate.gov.it/dp/api?v=' + unixTime())
cookieJar = s.cookies

print('Seleziono il tipo di incarico')
# payload = {'sceltaincarico': cfstudio + '-000', 'tipoincaricante' : 'incDiretto'}    
# r = s.post('https://ivaservizi.agenziaentrate.gov.it/portale/scelta-utenza-lavoro?p_auth='+ p_auth + '&p_p_id=SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet&p_p_lifecycle=1&p_p_state=normal&p_p_mode=view&p_p_col_id=column-1&p_p_col_count=1&_SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet_javax.portlet.action=incarichiAction', data=payload)

if profilo == 1:
# Delega Diretta
            payload = {'cf_inserito': cfcliente};
            r = s.post('https://ivaservizi.agenziaentrate.gov.it/portale/scelta-utenza-lavoro?p_auth='+ p_auth + '&p_p_id=SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet&p_p_lifecycle=1&p_p_state=normal&p_p_mode=view&p_p_col_id=column-1&p_p_col_count=1&_SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet_javax.portlet.action=delegaDirettaAction', data=payload);
            payload = {'cf_inserito': cfcliente, 'sceltapiva' : pivadiretta};    
            r = s.post('https://ivaservizi.agenziaentrate.gov.it/portale/scelta-utenza-lavoro?p_auth='+ p_auth + '&p_p_id=SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet&p_p_lifecycle=1&p_p_state=normal&p_p_mode=view&p_p_col_id=column-1&p_p_col_count=1&_SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet_javax.portlet.action=delegaDirettaAction', data=payload);
# Me stesso
elif profilo == 2:
            payload = {'sceltaincarico': cfstudio + '-000', 'tipoincaricante' : 'incDiretto'};
            r = s.post('https://ivaservizi.agenziaentrate.gov.it/portale/scelta-utenza-lavoro?p_auth='+ p_auth + '&p_p_id=SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet&p_p_lifecycle=1&p_p_state=normal&p_p_mode=view&p_p_col_id=column-1&p_p_col_count=1&_SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet_javax.portlet.action=meStessoAction', data=payload)
            payload = {'sceltaincarico': cfstudio + '-000', 'tipoincaricante' : 'incDiretto', 'sceltapiva' : pivadiretta};    
            r = s.post('https://ivaservizi.agenziaentrate.gov.it/portale/scelta-utenza-lavoro?p_auth='+ p_auth + '&p_p_id=SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet&p_p_lifecycle=1&p_p_state=normal&p_p_mode=view&p_p_col_id=column-1&p_p_col_count=1&_SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet_javax.portlet.action=meStessoAction', data=payload);
# Login per STUDIO ASSOCIATO
else:
            payload = {'sceltaincarico': cfstudio + '-000', 'tipoincaricante' : 'incDelega', 'cf_inserito': cfcliente};
            r = s.post('https://ivaservizi.agenziaentrate.gov.it/portale/scelta-utenza-lavoro?p_auth='+ p_auth + '&p_p_id=SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet&p_p_lifecycle=1&p_p_state=normal&p_p_mode=view&p_p_col_id=column-1&p_p_col_count=1&_SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet_javax.portlet.action=incarichiAction', data=payload);
            payload = {'sceltaincarico': cfstudio + '-000', 'tipoincaricante' : 'incDelega', 'cf_inserito': cfcliente, 'sceltapiva' : pivadiretta};
            r = s.post('https://ivaservizi.agenziaentrate.gov.it/portale/scelta-utenza-lavoro?p_auth='+ p_auth + '&p_p_id=SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet&p_p_lifecycle=1&p_p_state=normal&p_p_mode=view&p_p_col_id=column-1&p_p_col_count=1&_SceltaUtenzaLavoro_WAR_SceltaUtenzaLavoroportlet_javax.portlet.action=incarichiAction', data=payload);




print('Aderisco al servizio')
r = s.get('https://ivaservizi.agenziaentrate.gov.it/ser/api/fatture/v1/ul/me/adesione/stato/')
cookieJar = s.cookies

headers_token = {'x-xss-protection': '1; mode=block',
           'strict-transport-security': 'max-age=16070400; includeSubDomains',
           'x-content-type-options': 'nosniff',
           'x-frame-options': 'deny'}
r = s.get('https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/sc/tokenB2BCookie/get?v='+unixTime() , headers = headers_token )
cookieJar = s.cookies
tokens = r.headers

xb2bcookie = r.headers.get('x-b2bcookie')
xtoken = r.headers.get('x-token')


s.headers.update({'Host': 'ivaservizi.agenziaentrate.gov.it'})
s.headers.update({'Referer': 'https://ivaservizi.agenziaentrate.gov.it/cons/cons-web/?v=' + unixTime()})
s.headers.update({'Accept': 'application/json, text/plain, */*'})
s.headers.update({'Accept-Encoding': 'gzip, deflate, br'})
s.headers.update({'Accept-Language': 'it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7,fr;q=0.6'})
s.headers.update({'DNT': '1'})
s.headers.update({'X-XSS-Protection': '1; mode=block'})
s.headers.update({'Strict-Transport-Security': 'max-age=16070400; includeSubDomains'})
s.headers.update({'X-Content-Type-Options': 'nosniff'})
s.headers.update({'X-Frame-Options': 'deny'})
s.headers.update({'x-b2bcookie': xb2bcookie})
s.headers.update({'x-token': xtoken})

headers = {'Host': 'ivaservizi.agenziaentrate.gov.it',
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
           'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.119 Safari/537.36'}

print('Accetto le condizioni')
r = s.get('https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/disclaimer/accetta?v='+unixTime() , headers = headers_token )
cookieJar = s.cookies


#seleziona file 
## nome_file='IT02081640845_00001.xml'
nr_file = 0
print("Elenco file fatture massive da inviare: ", cfclientexmlnopath)##
ext = [".xml", ".XML"]
if cfclientexmlnopath.endswith(tuple(ext)):
     nome_file = cfclientexmlnopath
     # print("Percorso", os.path.join(dirs))
     print("Il nome file da inviare è", nome_file)
     with open('./inviomassivo/' + nome_file, "rb") as f:
         headers_file= { 'Host': 'ivaservizi.agenziaentrate.gov.it',
                         'Cache-Control': 'max-age=0',
                         'sec-ch-ua': '"Chromium";v="88", "Google Chrome";v="88", ";Not A Brand";v="99"',
                         'sec-ch-ua-mobile': '?0',
                         'Sec-Fetch-Site': 'same-origin',
                         'Sec-Fetch-Mode': 'cors',
                         'Sec-Fetch-User': '?1',
                         'Sec-Fetch-Dest': 'empty',
                         'Upgrade-Insecure-Requests': '1',
                         'accept': 'application/json, text/plain, */*',
                         'accept-encoding': 'gzip, deflate',
                         'accept-language': 'it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7,fr;q=0.6',
                         'Origin': 'https://ivaservizi.agenziaentrate.gov.it',
                         'x-frame-options': 'deny',
                         'x-b2bcookie': xb2bcookie,
                         'x-token': xtoken,
                         'X-XSS-Protection': '1; mode=block',
                         'Strict-Transport-Security': 'max-age=16070400; includeSubDomains',
                         'Content-Type': 'application/xml;charset=utf-8',
                         'connection': 'keep-alive',
                         'X-Frame-Options': 'deny',
                         'x-nome-file': nome_file,
                         'X-Content-Type-Options': 'nosniff',
                         'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.119 Safari/537.36'}    

         print("Contenuto", f)    
         r = s.post('https://ivaservizi.agenziaentrate.gov.it/cons/mass-services/rs/file/upload?tipoRichiesta=FATT',headers=headers_file, data=f)
         cookieJar = s.cookies
         print(r.status_code)
         if r.status_code == 500:
             print('Servizio dell''Agenzia delle Entrate non disponibile')
             print('Invio non andanto a buon fine, riprovare più tardi')
             print('Disconnessione in corso')
             r = s.get('https://ivaservizi.agenziaentrate.gov.it/portale/c/portal/logout')
             sys.exit()
         if r.status_code == 200:
             print('Invio file/files Fatture Massive inviato/i con successo!', nome_file)
             print("Codice invio Fatture Massive:", r.text)
             conservate = open(cfcliente+ "_fattura_massiva_inviati.csv", 'a')
             conservate.write(nome_file)
             conservate.write(",")
             conservate.write(r.text)
             conservate.write(",")
             conservate.write(str(now) + "\n")
             conservate.close()
             nr_file = nr_file + 1
             time.sleep(5)
             print("nr. files inviato/i --> ", nr_file)
             r = s.get('https://ivaservizi.agenziaentrate.gov.it/portale/c/portal/logout')
os.rename(cfclientexml, cfclientexml  + '_inviato_il_' + now.strftime("%Y-%m-%d"))
