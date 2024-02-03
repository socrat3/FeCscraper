# Downloader Fatture elettroniche passive ed attive (acquisto e vendite) per tutti i periodi

La nuova versione - pensata da un dott. commercialista per commercialisti ma anche per uso aziendale - funziona per scaricare tutte le fatture (passive ed attive italiane ed estere a disposizione e non e per decodificare il file p7m in xml) con lo scaricamento del file delle notifiche. La versione è notevolmente migliorata da un punto di vista grafico e della velocità.

ScarFec4.py è sempre a riga di comando e scarica per la singola azienda per un periodo (anche superiore al trimestre) tutte le fatture emesse e ricevute e quelle a disposizione ed estere. Sono state implementate. I profili sono sempre INCARIO DIRETTO E studio associato o ME stesso. La sintassi è stata modificata.

Se avete uno studio associato dovete modificare il profilo nel file

es.
ScarFec4.py TXXXXX PIN_entratel PASSW_ENTRATEL P_IVA_STUDIO_COMMERCIALISTA data_inizio_fatture data_finale_fatture CF_CLIENTE P_IVA_CLIENTE 3 TUTTI

lanciare da prompt

ScarFec4.py T123456 674C12345 KKKKK123 09081640845 01122023 03022024 VLLVCN87A55A089X 01521820949 3 TUTTI

Dovete scaricare python per windows e i moduli che vengono richiamati. La licenza è GPL se fate delle modifiche condividetele inviandole alla mia email o su git
per decodificare file p7m dovete installare

FireDaemon-OpenSSL-x64-3.2.1.exe
