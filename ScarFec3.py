## Licenza Libera progetto originario di Claudio Pizzillo
## Modifiche e riadattamenti da Salvatore Crapanzano
## 01/08/23 Altre modifiche da Uzirox## 
## V. 3.0 del 21-01-2024  - Intermediari e Diretto e Studio Associato
## 

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import re
import time
from datetime import timedelta, datetime, tzinfo, timezone
import sys
import pytz
import json
import os
from clint.textui import colored, puts
from tqdm import *

    
def unixTime():
    dt = datetime.now(tz=pytz.utc)
    return str(int(dt.timestamp() * 1000))
try:
    if len(sys.argv) < 10:
        print('Utilizzo: fec.py(fec.exe) CodiceFiscale/CodiceEntratel PIN Password PartitaIVA DataDal DataAl FOL/ENT')
        print('Esempio: TXXXXXX PIN PASSWORD COD_FISCALE 01012023 31032023 CF_CLIENTE PIVA_CLIENTE {1/2} [A-V-T')
        sys.exit()

    profilo = 1 # Impostare il profilo Delega diretta codice 1, Me stesso 2, Studio Associato Default
    CF = sys.argv[1]
    PIN = sys.argv[2]
    Password  = sys.argv[3]
    cfstudio  = sys.argv[4]
    Dal = sys.argv[5]
    Al = sys.argv[6]
    cfcliente = sys.argv[7]
    pivadiretta = sys.argv[8]
    tipo = int(sys.argv[9]) # 1 per data di ricezione 2 (QUALSIASI VALORE DIVERSA DA 1) per data di emissione
    VenOAcq = sys.argv[10]  # "v" per sole vendite, "a" per soli acquisti, ALTRIMENTI T per tutti e due

    s = requests.Session()
    s.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.119 Safari/537.36'})
    s.headers.update({'Connection': 'keep-alive'})

    cookie_obj1 = requests.cookies.create_cookie(domain='ivaservizi.agenziaentrate.gov.it',name='LFR_SESSION_STATE_20159',value='expired')
    s.cookies.set_cookie(cookie_obj1)
    cookie_obj2 = requests.cookies.create_cookie(domain='ivaservizi.agenziaentrate.gov.it',name='LFR_SESSION_STATE_10811916',value=unixTime())
    s.cookies.set_cookie(cookie_obj2)
    r = s.get('https://ivaservizi.agenziaentrate.gov.it/portale/web/guest', verify=False)

    if r.status_code == 200:
        puts(colored.yellow('Collegamento alla homepage. Avvio.'))
    else:
        puts(colored.red('Collegamento alla homepage non riuscito: uscita.'))
        sys.exit()
    cookieJar = s.cookies

    print('Effettuo il login')
    payload = {'_58_saveLastPath': 'false', '_58_redirect' : '', '_58_doActionAfterLogin': 'false', '_58_login': CF , '_58_pin': PIN, '_58_password': Password}    
    r = s.post('https://ivaservizi.agenziaentrate.gov.it/portale/home?p_p_id=58&p_p_lifecycle=1&p_p_state=normal&p_p_mode=view&p_p_col_id=column-1&p_p_col_pos=3&p_p_col_count=4&_58_struts_action=%2Flogin%2Flogin', data=payload)
    cookieJar = s.cookies

    liferay = re.findall(r"Liferay.authToken = '.*';", r.text)[0]
    p_auth = liferay.replace("Liferay.authToken = '","")
    p_auth = p_auth.replace("';", "")

    r = s.get('https://ivaservizi.agenziaentrate.gov.it/dp/api?v=' + unixTime())
# controlla fase di login 
    if r.status_code == 200:
        puts(colored.yellow('Login riuscito. Con credenzilali ENTRATEL'))
    else:
        puts(colored.red('Login non riuscito: uscita.')) 
        sys.exit()

    
    cookieJar = s.cookies

    print('Seleziono il tipo di incarico')
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
# ADERISCO AL SERVIZIO - NA CAMURRIA!
    if r.status_code == 200:
        puts(colored.yellow('Adesione riuscita ai servizi AdE.'))
    else:
        puts(colored.red('Adesione ai servizi AdE non riuscita: uscita.')) 
        sys.exit()
    
    cookieJar = s.cookies 

    headers_token = {'x-xss-protection': '1; mode=block',
               'strict-transport-security': 'max-age=16070400; includeSubDomains',
               'x-content-type-options': 'nosniff',
               'x-frame-options': 'deny'}
    r = s.get('https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/sc/tokenB2BCookie/get?v='+unixTime() , headers = headers_token )
    if r.status_code == 200:
        puts(colored.yellow('B2B Cookie ottenuto'))
    else:
        puts(colored.red('B2B Cookie non ottenuto: uscita.')) 
        sys.exit()
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




    if VenOAcq != "V":
        #===============================================================================================
        # FATTURE MESSE A DISPOSIZIONE
        #===============================================================================================
        print('Scarico il json delle fatture ricevute e messe a disposizione per la partita IVA ' + cfcliente)
        r = s.get('https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fe/mc/dal/'+Dal+'/al/'+Al+'?v=' + unixTime(), headers = headers)
        if r.status_code == 200:
            puts(colored.yellow('Lista ottenuta.'))
        else:
            puts(colored.red('Lista non ottenuta: uscita.')) 
            sys.exit()


        with open('fe_ricevute_disposizione_' + cfcliente + '.json', 'wb') as f:
            f.write(r.content)
            print('Inizio a scaricare le fatture ricevute e messe a disposizione!')
        path = r'FatturePassive_' + cfcliente
        if not os.path.exists(path):
            os.makedirs(path)
        with open('fe_ricevute_disposizione_'+ cfcliente +'.json') as data_file:    
            data = json.load(data_file)
            #print('Inizio a scaricare ' + str(data['totaleFatture']) + ' fatture dal ' + data['dataRicercaDa'] + ' al ' + data['dataRicercaA'] + ' per un massimo di ' + str(data['limiteBloccoTotaleFatture']) + ' fatture scaricabili.')#
            numero_fatture = 0
            numero_notifiche = 0
            for fattura in data['fatture']:
                fatturaFile = fattura['tipoInvio']+fattura['idFattura']
                r = s.get('https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fatture/file/'+fatturaFile+'?tipoFile=FILE_FATTURA&download=1&v='+unixTime() , headers = headers_token )
                if r.status_code == 200:
                    numero_fatture = numero_fatture + 1
                    d = r.headers['content-disposition']
                    fname = re.findall("filename=(.+)", d)
                    print('Downloading ' + fname[0])
                    print('Totale fatture messe a disposizione scaricate: ', numero_fatture)
                    with open(path + '/' + fname[0], 'wb') as f:
                        f.write(r.content)              
        print('Totale fatture messe a disposizione scaricate: ', numero_fatture)




        #===============================================================================================
        # FATTURE RICEVUTE
        #===============================================================================================
        if tipo == 1:
        # r = s.get('https://ivaservizi.agenziaentrate.gov.it/ser/api/monitoraggio/v1/monitoraggio/fatture/?v='+unixTime()+'&idFiscCedente=&idFiscDestinatario=&idFiscEmittente=&idFiscTrasmittente=&idSdi=&perPage=10&start=1&statoFile=&tipoFattura=EMESSA')
             print('Scarico il json delle fatture ricevute per data di ricezione la partita IVA ' + cfcliente)
             r = s.get('https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fe/ricevute/dal/'+Dal+'/al/'+Al+'/ricerca/ricezione?v=' + unixTime(), headers = headers)
        else:     
             print('Scarico il json delle fatture ricevute per data di emissione per la partita IVA ' + cfcliente)
             r = s.get('https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fe/ricevute/dal/'+Dal+'/al/'+Al+'/ricerca/emissione?v=' + unixTime(), headers = headers)

        with open('fe_ricevute_'+ cfcliente +'.json', 'wb') as f:
            f.write(r.content)
            
        print('Inizio a scaricare le fatture ricevute')
        path = r'FatturePassive_' + cfcliente
        if not os.path.exists(path):
            os.makedirs(path)
        with open('fe_ricevute_'+ cfcliente +'.json') as data_file:    
            data = json.load(data_file)
            numero_fatture = 0
            numero_notifiche = 0
            for fattura in data['fatture']:
                fatturaFile = fattura['tipoInvio']+fattura['idFattura']
                r = s.get('https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fatture/file/'+fatturaFile+'?tipoFile=FILE_FATTURA&download=1&v='+unixTime() , headers = headers_token )
                if r.status_code == 200:
                    numero_fatture = numero_fatture + 1
                    d = r.headers['content-disposition']
                    fname = re.findall("filename=(.+)", d)
                    print('Downloading ' + fname[0])
                    print('Totale fatture RICEVUTE scaricate: ', numero_fatture)
                    with open(path + '/' + fname[0], 'wb') as f:
                        f.write(r.content)          
        print('Totale fatture RICEVUTE scaricate: ', numero_fatture)


    #=============# FATTURE TRANSFRONTALIERE RICEVUTE=======#
        print('Scarico il json delle fatture  Transfrontaliere Ricevute per la Partita IVA ' + cfcliente)
        r = s.get('https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/ft/ricevute/dal/'+Dal+'/al/'+Al+'?v=' + unixTime(), headers = headers)

        with open('fe_ricevutetr_'+ cfcliente +'.json', 'wb') as f:
            f.write(r.content)
            
        print('Inizio a scaricare le fatture transfrontaliere ricevute')
        path = r'FatturePassive_' + cfcliente
        if not os.path.exists(path):
            os.makedirs(path)
        with open('fe_ricevutetr_'+ cfcliente +'.json') as data_file:    
            data = json.load(data_file)
            numero_fatture = 0
            numero_notifiche = 0
            for fattura in data['fatture']:
                fatturaFile = fattura['tipoInvio']+fattura['idFattura']
                r = s.get('https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fatture/file/'+fatturaFile+'?tipoFile=FILE_FATTURA&download=1&v='+unixTime() , headers = headers_token )
                if r.status_code == 200:
                    numero_fatture = numero_fatture + 1
                    d = r.headers['content-disposition']
                    fname = re.findall("filename=(.+)", d)
                    print('Downloading ' + fname[0])
                    print('Totale fatture TRANSFRONTALIERE RICEVUTE scaricate: ', numero_fatture)
                    with open(path + '/' + fname[0], 'wb') as f:
                        f.write(r.content)
        print('Per il cliente: ', cfcliente)
        print('Totale fatture TRANSFRONTALIERE RICEVUTE scaricate: ', numero_fatture)


    if VenOAcq != "A":
    #========================================================================================
    # FATTURE EMESSE
    #=========================================================================================
        print('Scarico il json delle fatture Emesse per la Partita IVA ' + cfcliente)
        r = s.get('https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fe/emesse/dal/'+Dal+'/al/'+Al+'?v=' + unixTime(), headers = headers)

        with open('fe_emesse_'+ cfcliente +'.json', 'wb') as f:
            f.write(r.content)
            
        print('Inizio a scaricare le fatture emesse')
        path = r'FattureEmesse_' + cfcliente
        if not os.path.exists(path):
            os.makedirs(path)
        with open('fe_emesse.json') as data_file:    
            data = json.load(data_file)
            numero_fatture = 0
            numero_notifiche = 0
            for fattura in data['fatture']:
                fatturaFile = fattura['tipoInvio']+fattura['idFattura']
                r = s.get('https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fatture/file/'+fatturaFile+'?tipoFile=FILE_FATTURA&download=1&v='+unixTime() , headers = headers_token )
                if r.status_code == 200:
                    numero_fatture = numero_fatture + 1
                    d = r.headers['content-disposition']
                    fname = re.findall("filename=(.+)", d)
                    print('Downloading ' + fname[0])
                    print('Totale fatture EMESSE scaricate: ', numero_fatture)
                    with open(path + '/' + fname[0], 'wb') as f:
                        f.write(r.content)             
        print('Per il cliente: ', cfcliente)
        print('Totale fatture EMESSE scaricate: ', numero_fatture)


    #========================================================================================
    # FATTURE TRANSFRONTALIERE EMESSE
    #========================================================================================
        print('Scarico il json delle fatture  Transfrontaliere Emesse per la Partita IVA ' + cfcliente)
        r = s.get('https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/ft/emesse/dal/'+Dal+'/al/'+Al+'?v=' + unixTime(), headers = headers)

        with open('fe_emessetr_'+ cfcliente +'.json', 'wb') as f:
            f.write(r.content)
            
        print('Inizio a scaricare le fatture transfrontaliere emesse')
        path = r'FattureEmesse_' + cfcliente + "_" + Dal
        if not os.path.exists(path):
            os.makedirs(path)
        with open('fe_emessetr_'+ cfcliente +'.json') as data_file:    
            data = json.load(data_file)
            numero_fatture = 0
            numero_notifiche = 0
            for fattura in data['fatture']:
                fatturaFile = fattura['tipoInvio']+fattura['idFattura']
                r = s.get('https://ivaservizi.agenziaentrate.gov.it/cons/cons-services/rs/fatture/file/'+fatturaFile+'?tipoFile=FILE_FATTURA&download=1&v='+unixTime() , headers = headers_token )
                if r.status_code == 200:
                    numero_fatture = numero_fatture + 1
                    d = r.headers['content-disposition']
                    fname = re.findall("filename=(.+)", d)
                    print('Downloading ' + fname[0])
                    print('Totale fatture TRANSFRONTALIERE EMESSE scaricate: ', numero_fatture)
                    with open(path + '/' + fname[0], 'wb') as f:
                        f.write(r.content)
        print('Per il cliente: ', cfcliente)
        print('Totale fatture TRANSFRONTALIERE EMESSE scaricate: ', numero_fatture)

except KeyboardInterrupt:
    print("Programma terminato manualmente!")

sys.exit()