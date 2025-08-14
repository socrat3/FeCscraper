#!/usr/bin/env python3
"""
Estrattore JSON per Fatture Elettroniche
Estrae informazioni su ritenute, cassa previdenza, IVA e totali
Integrazione con xml_fatture_processor_v12 e rf_export
"""

import json
import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any
import logging
from collections import defaultdict

class FatturaJSONExtractor:
    """Estrae dati chiave dalle fatture XML e crea file JSON individuali"""
    
    def __init__(self, input_dir: str = None, output_dir: str = None):
        self.input_dir = Path(input_dir) if input_dir else Path.cwd() / 'fatture_xml'
        self.output_dir = Path(output_dir) if output_dir else Path.cwd() / 'fatture_json'
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('fatture_json_extractor.log', encoding='utf-8'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Namespace comuni fattura elettronica
        self.namespaces = {
            'p': 'http://ivaservizi.agenziaentrate.gov.it/docs/xsd/fatture/v1.2',
            'ns2': 'http://ivaservizi.agenziaentrate.gov.it/docs/xsd/fatture/v1.2',
            'ns3': 'http://ivaservizi.agenziaentrate.gov.it/docs/xsd/fatture/v1.0',
        }
        
    def strip_namespace(self, tag: str) -> str:
        """Rimuove namespace dal tag XML"""
        return tag.split('}')[-1] if '}' in tag else tag
    
    def find_element_recursive(self, root: ET.Element, target_tag: str) -> Optional[ET.Element]:
        """Cerca un elemento ricorsivamente ignorando i namespace"""
        for elem in root.iter():
            if self.strip_namespace(elem.tag) == target_tag:
                return elem
        return None
    
    def get_text_value(self, element: Optional[ET.Element], default: str = '') -> str:
        """Ottiene il valore testuale di un elemento"""
        if element is not None and element.text:
            return element.text.strip()
        return default
    
    def parse_decimal(self, value: str, default: float = 0.0) -> float:
        """Converte stringa in float gestendo formati italiani"""
        if not value:
            return default
        try:
            # Gestisce sia punto che virgola come separatore decimale
            value = value.replace(',', '.')
            return float(value)
        except ValueError:
            return default
    
    def extract_fattura_data(self, file_path: Path) -> Dict[str, Any]:
        """Estrae tutti i dati rilevanti da una fattura XML"""
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            fattura_data = {
                'nome_file': file_path.name,
                'percorso_originale': str(file_path),
                'data_estrazione': datetime.now().isoformat(),
                'dati_generali': {},
                'cedente_prestatore': {},
                'cessionario_committente': {},
                'ritenute': {},
                'cassa_previdenza': {},
                'riepilogo_iva': [],
                'totali': {},
                'pagamenti': [],
                'ha_ritenuta': False,
                'ha_cassa_previdenza': False,
                'errori': []
            }
            
            # 1. DATI GENERALI DOCUMENTO
            dati_generali = self.find_element_recursive(root, 'DatiGeneraliDocumento')
            if dati_generali:
                fattura_data['dati_generali'] = {
                    'tipo_documento': self.get_text_value(dati_generali.find('.//TipoDocumento')),
                    'divisa': self.get_text_value(dati_generali.find('.//Divisa')),
                    'data': self.get_text_value(dati_generali.find('.//Data')),
                    'numero': self.get_text_value(dati_generali.find('.//Numero')),
                    'importo_totale_documento': self.parse_decimal(
                        self.get_text_value(dati_generali.find('.//ImportoTotaleDocumento'))
                    )
                }
                
                # RITENUTE
                dati_ritenuta = dati_generali.find('.//DatiRitenuta')
                if dati_ritenuta:
                    fattura_data['ha_ritenuta'] = True
                    fattura_data['ritenute'] = {
                        'tipo_ritenuta': self.get_text_value(dati_ritenuta.find('.//TipoRitenuta')),
                        'importo_ritenuta': self.parse_decimal(
                            self.get_text_value(dati_ritenuta.find('.//ImportoRitenuta'))
                        ),
                        'aliquota_ritenuta': self.parse_decimal(
                            self.get_text_value(dati_ritenuta.find('.//AliquotaRitenuta'))
                        ),
                        'causale_pagamento': self.get_text_value(dati_ritenuta.find('.//CausalePagamento'))
                    }
                
                # CASSA PREVIDENZA
                dati_cassa = dati_generali.find('.//DatiCassaPrevidenziale')
                if dati_cassa:
                    fattura_data['ha_cassa_previdenza'] = True
                    fattura_data['cassa_previdenza'] = {
                        'tipo_cassa': self.get_text_value(dati_cassa.find('.//TipoCassa')),
                        'aliquota_cassa': self.parse_decimal(
                            self.get_text_value(dati_cassa.find('.//AlCassa'))
                        ),
                        'importo_contributo_cassa': self.parse_decimal(
                            self.get_text_value(dati_cassa.find('.//ImportoContributoCassa'))
                        ),
                        'imponibile_cassa': self.parse_decimal(
                            self.get_text_value(dati_cassa.find('.//ImponibileCassa'))
                        ),
                        'aliquota_iva': self.parse_decimal(
                            self.get_text_value(dati_cassa.find('.//AliquotaIVA'))
                        ),
                        'ritenuta': self.get_text_value(dati_cassa.find('.//Ritenuta')),
                        'natura': self.get_text_value(dati_cassa.find('.//Natura')),
                        'riferimento_amministrazione': self.get_text_value(
                            dati_cassa.find('.//RiferimentoAmministrazione')
                        )
                    }
            
            # 2. CEDENTE/PRESTATORE
            cedente = self.find_element_recursive(root, 'CedentePrestatore')
            if cedente:
                dati_anagrafici = cedente.find('.//DatiAnagrafici')
                if dati_anagrafici:
                    id_fiscale = dati_anagrafici.find('.//IdFiscaleIVA')
                    fattura_data['cedente_prestatore'] = {
                        'partita_iva': self.get_text_value(id_fiscale.find('.//IdCodice')) if id_fiscale else '',
                        'codice_fiscale': self.get_text_value(dati_anagrafici.find('.//CodiceFiscale')),
                        'denominazione': self.get_text_value(dati_anagrafici.find('.//Denominazione')),
                        'nome': self.get_text_value(dati_anagrafici.find('.//Nome')),
                        'cognome': self.get_text_value(dati_anagrafici.find('.//Cognome'))
                    }
            
            # 3. CESSIONARIO/COMMITTENTE
            cessionario = self.find_element_recursive(root, 'CessionarioCommittente')
            if cessionario:
                dati_anagrafici = cessionario.find('.//DatiAnagrafici')
                if dati_anagrafici:
                    id_fiscale = dati_anagrafici.find('.//IdFiscaleIVA')
                    fattura_data['cessionario_committente'] = {
                        'partita_iva': self.get_text_value(id_fiscale.find('.//IdCodice')) if id_fiscale else '',
                        'codice_fiscale': self.get_text_value(dati_anagrafici.find('.//CodiceFiscale')),
                        'denominazione': self.get_text_value(dati_anagrafici.find('.//Denominazione')),
                        'nome': self.get_text_value(dati_anagrafici.find('.//Nome')),
                        'cognome': self.get_text_value(dati_anagrafici.find('.//Cognome'))
                    }
            
            # 4. RIEPILOGO IVA
            dati_beni_servizi = self.find_element_recursive(root, 'DatiBeniServizi')
            if dati_beni_servizi:
                for riepilogo in dati_beni_servizi.findall('.//DatiRiepilogo'):
                    riepilogo_data = {
                        'aliquota_iva': self.parse_decimal(
                            self.get_text_value(riepilogo.find('.//AliquotaIVA'))
                        ),
                        'imponibile_importo': self.parse_decimal(
                            self.get_text_value(riepilogo.find('.//ImponibileImporto'))
                        ),
                        'imposta': self.parse_decimal(
                            self.get_text_value(riepilogo.find('.//Imposta'))
                        ),
                        'natura': self.get_text_value(riepilogo.find('.//Natura')),
                        'spese_accessorie': self.parse_decimal(
                            self.get_text_value(riepilogo.find('.//SpeseAccessorie'))
                        ),
                        'arrotondamento': self.parse_decimal(
                            self.get_text_value(riepilogo.find('.//Arrotondamento'))
                        ),
                        'esigibilita_iva': self.get_text_value(riepilogo.find('.//EsigibilitaIVA')),
                        'riferimento_normativo': self.get_text_value(
                            riepilogo.find('.//RiferimentoNormativo')
                        )
                    }
                    fattura_data['riepilogo_iva'].append(riepilogo_data)
            
            # 5. CALCOLO TOTALI
            totale_imponibile = sum(r['imponibile_importo'] for r in fattura_data['riepilogo_iva'])
            totale_iva = sum(r['imposta'] for r in fattura_data['riepilogo_iva'])
            totale_documento = fattura_data['dati_generali'].get('importo_totale_documento', 0)
            
            # Se non c'è il totale documento, lo calcoliamo
            if totale_documento == 0:
                totale_documento = totale_imponibile + totale_iva
                if fattura_data['ha_cassa_previdenza']:
                    totale_documento += fattura_data['cassa_previdenza'].get('importo_contributo_cassa', 0)
            
            # Calcolo totale a pagare
            totale_a_pagare = totale_documento
            if fattura_data['ha_ritenuta']:
                totale_a_pagare -= fattura_data['ritenute'].get('importo_ritenuta', 0)
            
            fattura_data['totali'] = {
                'totale_imponibile': round(totale_imponibile, 2),
                'totale_iva': round(totale_iva, 2),
                'totale_documento': round(totale_documento, 2),
                'totale_a_pagare': round(totale_a_pagare, 2),
                'totale_ritenute': round(fattura_data['ritenute'].get('importo_ritenuta', 0), 2) if fattura_data['ha_ritenuta'] else 0,
                'totale_cassa_previdenza': round(fattura_data['cassa_previdenza'].get('importo_contributo_cassa', 0), 2) if fattura_data['ha_cassa_previdenza'] else 0
            }
            
            # 6. DATI PAGAMENTO
            dati_pagamento = self.find_element_recursive(root, 'DatiPagamento')
            if dati_pagamento:
                for dettaglio in dati_pagamento.findall('.//DettaglioPagamento'):
                    pagamento_data = {
                        'beneficiario': self.get_text_value(dettaglio.find('.//Beneficiario')),
                        'modalita_pagamento': self.get_text_value(dettaglio.find('.//ModalitaPagamento')),
                        'data_riferimento_termini_pagamento': self.get_text_value(
                            dettaglio.find('.//DataRiferimentoTerminiPagamento')
                        ),
                        'giorni_termini_pagamento': self.get_text_value(
                            dettaglio.find('.//GiorniTerminiPagamento')
                        ),
                        'data_scadenza_pagamento': self.get_text_value(
                            dettaglio.find('.//DataScadenzaPagamento')
                        ),
                        'importo_pagamento': self.parse_decimal(
                            self.get_text_value(dettaglio.find('.//ImportoPagamento'))
                        ),
                        'iban': self.get_text_value(dettaglio.find('.//IBAN')),
                        'abi': self.get_text_value(dettaglio.find('.//ABI')),
                        'cab': self.get_text_value(dettaglio.find('.//CAB')),
                        'bic': self.get_text_value(dettaglio.find('.//BIC'))
                    }
                    fattura_data['pagamenti'].append(pagamento_data)
            
            return fattura_data
            
        except ET.ParseError as e:
            self.logger.error(f"Errore parsing XML {file_path}: {e}")
            return {
                'nome_file': file_path.name,
                'errore': f"Errore parsing XML: {str(e)}"
            }
        except Exception as e:
            self.logger.error(f"Errore generico elaborazione {file_path}: {e}")
            return {
                'nome_file': file_path.name,
                'errore': f"Errore generico: {str(e)}"
            }
    
    def save_json(self, fattura_data: Dict, source_path: Path, preserve_structure: bool = True) -> bool:
        """Salva i dati della fattura in formato JSON mantenendo la struttura delle cartelle"""
        try:
            # Crea nome file basato sul nome originale
            original_name = source_path.stem  # Nome senza estensione
            json_filename = f"{original_name}.json"
            
            if preserve_structure:
                # Calcola il percorso relativo dalla directory di input
                relative_path = source_path.relative_to(self.input_dir).parent
                
                # Crea la stessa struttura nella directory di output
                # ma aggiungi una sottocartella 'json' per separare i JSON dagli XML
                output_subdir = self.output_dir / relative_path / 'json'
                output_subdir.mkdir(parents=True, exist_ok=True)
                
                output_path = output_subdir / json_filename
            else:
                # Modalità flat: tutti i JSON in una cartella
                output_path = self.output_dir / json_filename
            
            # Aggiungi il percorso relativo nei dati
            fattura_data['percorso_relativo'] = str(relative_path)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(fattura_data, f, ensure_ascii=False, indent=2)
            
            self.logger.info(f"Salvato JSON: {output_path}")
            return True, output_path
            
        except Exception as e:
            self.logger.error(f"Errore salvataggio JSON: {e}")
            return False, None
    
    def process_directory(self, input_dir: Path = None, preserve_structure: bool = True, 
                         filter_ritenute: bool = False, filter_cassa: bool = False) -> Dict[str, Any]:
        """
        Processa tutti i file XML in una directory e sottocartelle
        
        Args:
            input_dir: Directory di input (usa self.input_dir se None)
            preserve_structure: Se True, mantiene la struttura delle cartelle
        """
        if input_dir is None:
            input_dir = self.input_dir
        
        # Assicurati che input_dir sia un Path assoluto per il calcolo dei percorsi relativi
        self.input_dir = Path(input_dir).resolve()
        
        stats = {
            'totale_file': 0,
            'file_processati': 0,
            'file_con_ritenuta': 0,
            'file_con_cassa_previdenza': 0,
            'errori': 0,
            'totale_ritenute': 0.0,
            'totale_cassa_previdenza': 0.0,
            'dettagli_fatture': [],
            'struttura_cartelle': defaultdict(int)
        }
        
        # Cerca tutti i file XML ricorsivamente
        xml_files = list(self.input_dir.glob('**/*.xml'))
        
        # Filtra i metadati
        xml_files = [f for f in xml_files if 'METADATO' not in f.name.upper()]
        
        stats['totale_file'] = len(xml_files)
        
        print(f"\n📂 Analisi directory: {self.input_dir}")
        print(f"📊 Trovati {len(xml_files)} file XML da processare (esclusi metadati)")
        
        # Mostra struttura trovata
        subdirs = set()
        for xml_file in xml_files:
            try:
                relative = xml_file.relative_to(self.input_dir).parent
                if str(relative) != '.':
                    subdirs.add(str(relative))
            except:
                pass
        
        if subdirs:
            print(f"📁 Sottocartelle trovate: {len(subdirs)}")
            for subdir in sorted(subdirs)[:5]:  # Mostra prime 5
                print(f"   └── {subdir}")
            if len(subdirs) > 5:
                print(f"   └── ... e altre {len(subdirs)-5} cartelle")
        
        print("=" * 60)
        
        # Processa ogni file
        for i, xml_file in enumerate(xml_files, 1):
            # Calcola percorso relativo per display
            try:
                relative_display = xml_file.relative_to(self.input_dir)
            except:
                relative_display = xml_file.name
            
            print(f"\n[{i}/{len(xml_files)}] 📄 {relative_display}")
            
            # Estrai dati
            fattura_data = self.extract_fattura_data(xml_file)
            
            if 'errore' in fattura_data:
                stats['errori'] += 1
                print(f"   ❌ Errore: {fattura_data['errore']}")
                continue
            
            # Salva JSON mantenendo struttura
            success, output_path = self.save_json(fattura_data, xml_file, preserve_structure)
            
            if success:
                stats['file_processati'] += 1
                
                # Traccia struttura cartelle
                if output_path:
                    relative_folder = output_path.relative_to(self.output_dir).parent
                    stats['struttura_cartelle'][str(relative_folder)] += 1
                
                # Aggiorna statistiche
                if fattura_data['ha_ritenuta']:
                    stats['file_con_ritenuta'] += 1
                    stats['totale_ritenute'] += fattura_data['ritenute'].get('importo_ritenuta', 0)
                
                if fattura_data['ha_cassa_previdenza']:
                    stats['file_con_cassa_previdenza'] += 1
                    stats['totale_cassa_previdenza'] += fattura_data['cassa_previdenza'].get('importo_contributo_cassa', 0)
                
                # Aggiungi riepilogo con percorso
                riepilogo = {
                    'file': fattura_data['nome_file'],
                    'percorso': fattura_data.get('percorso_relativo', ''),
                    'numero': fattura_data['dati_generali'].get('numero'),
                    'data': fattura_data['dati_generali'].get('data'),
                    'totale': fattura_data['totali'].get('totale_documento'),
                    'ha_ritenuta': fattura_data['ha_ritenuta'],
                    'importo_ritenuta': fattura_data['ritenute'].get('importo_ritenuta', 0) if fattura_data['ha_ritenuta'] else 0,
                    'ha_cassa': fattura_data['ha_cassa_previdenza'],
                    'importo_cassa': fattura_data['cassa_previdenza'].get('importo_contributo_cassa', 0) if fattura_data['ha_cassa_previdenza'] else 0
                }
                stats['dettagli_fatture'].append(riepilogo)
                
                # Stampa info compatte
                print(f"   ✅ {fattura_data['dati_generali'].get('numero')} del {fattura_data['dati_generali'].get('data')}")
                print(f"   💰 €{fattura_data['totali'].get('totale_documento'):.2f}", end="")
                
                if fattura_data['ha_ritenuta']:
                    print(f" | RIT: €{fattura_data['ritenute'].get('importo_ritenuta'):.2f}", end="")
                
                if fattura_data['ha_cassa_previdenza']:
                    print(f" | CASSA: €{fattura_data['cassa_previdenza'].get('importo_contributo_cassa'):.2f}", end="")
                
                print(f" | Netto: €{fattura_data['totali'].get('totale_a_pagare'):.2f}")
                
                if output_path:
                    relative_json = output_path.relative_to(self.output_dir)
                    print(f"   💾 Salvato in: {relative_json}")
        
        return stats
    
    def generate_summary_report(self, stats: Dict, filter_ritenute: bool = False, 
                               filter_cassa: bool = False) -> None:
        """Genera report riepilogativo con dettagli sui filtri applicati"""
        report_path = self.output_dir / f"riepilogo_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        # Prepara lista fatture con ritenuta/cassa per export separato
        fatture_con_ritenuta = [f for f in stats['dettagli_fatture'] if f['ha_ritenuta']]
        fatture_con_cassa = [f for f in stats['dettagli_fatture'] if f['ha_cassa']]
        fatture_con_entrambe = [f for f in stats['dettagli_fatture'] if f['ha_ritenuta'] and f['ha_cassa']]
        
        # Crea report dettagliato
        report = {
            'data_elaborazione': datetime.now().isoformat(),
            'directory_input': str(self.input_dir),
            'directory_output': str(self.output_dir),
            'filtri_applicati': {
                'solo_ritenute': filter_ritenute,
                'solo_cassa': filter_cassa
            },
            'statistiche': {
                'totale_file': stats['totale_file'],
                'file_processati': stats['file_processati'],
                'file_saltati_per_filtro': stats.get('file_saltati_per_filtro', 0),
                'file_con_ritenuta': stats['file_con_ritenuta'],
                'file_con_cassa_previdenza': stats['file_con_cassa_previdenza'],
                'file_con_entrambe': len(fatture_con_entrambe),
                'errori': stats['errori']
            },
            'totali': {
                'totale_ritenute': round(stats['totale_ritenute'], 2),
                'totale_cassa_previdenza': round(stats['totale_cassa_previdenza'], 2)
            },
            'struttura_output': dict(stats.get('struttura_cartelle', {})),
            'dettagli_fatture': stats['dettagli_fatture'],
            'fatture_con_ritenuta': fatture_con_ritenuta,
            'fatture_con_cassa': fatture_con_cassa,
            'fatture_con_entrambe': fatture_con_entrambe
        }
        
        # Salva report principale
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        
        # Salva report specifici se ci sono risultati
        if fatture_con_ritenuta:
            ritenute_path = self.output_dir / f"fatture_con_ritenuta_{datetime.now().strftime('%Y%m%d')}.json"
            with open(ritenute_path, 'w', encoding='utf-8') as f:
                json.dump({
                    'data_estrazione': datetime.now().isoformat(),
                    'totale_fatture': len(fatture_con_ritenuta),
                    'totale_ritenute': round(sum(f['importo_ritenuta'] for f in fatture_con_ritenuta), 2),
                    'fatture': fatture_con_ritenuta
                }, f, ensure_ascii=False, indent=2)
        
        if fatture_con_cassa:
            cassa_path = self.output_dir / f"fatture_con_cassa_{datetime.now().strftime('%Y%m%d')}.json"
            with open(cassa_path, 'w', encoding='utf-8') as f:
                json.dump({
                    'data_estrazione': datetime.now().isoformat(),
                    'totale_fatture': len(fatture_con_cassa),
                    'totale_cassa': round(sum(f['importo_cassa'] for f in fatture_con_cassa), 2),
                    'fatture': fatture_con_cassa
                }, f, ensure_ascii=False, indent=2)
        
        # Stampa riepilogo
        print("\n" + "=" * 60)
        print("📊 RIEPILOGO ELABORAZIONE")
        print("=" * 60)
        
        if filter_ritenute or filter_cassa:
            print("🔍 FILTRI APPLICATI:")
            if filter_ritenute:
                print("   ✓ Solo fatture con ritenuta")
            if filter_cassa:
                print("   ✓ Solo fatture con cassa previdenza")
            print(f"   📄 File saltati per filtro: {stats.get('file_saltati_per_filtro', 0)}")
            print()
        
        print(f"📁 File totali: {stats['totale_file']}")
        print(f"✅ File processati: {stats['file_processati']}")
        print(f"❌ Errori: {stats['errori']}")
        
        print(f"\n🏦 FATTURE CON RITENUTA D'ACCONTO: {stats['file_con_ritenuta']}")
        if fatture_con_ritenuta:
            print(f"   Totale ritenute: €{stats['totale_ritenute']:.2f}")
            if len(fatture_con_ritenuta) > 0:
                print(f"   Top {min(5, len(fatture_con_ritenuta))} ritenute più alte:")
                for f in sorted(fatture_con_ritenuta, key=lambda x: x['importo_ritenuta'], reverse=True)[:5]:
                    aliquota = f.get('aliquota_ritenuta', 0)
                    cedente = f.get('cedente', 'N/D')
                    if cedente and len(cedente) > 30:
                        cedente = cedente[:30] + '...'
                    print(f"      • {f['numero']} ({f['data']}) - €{f['importo_ritenuta']:.2f}", end="")
                    if aliquota > 0:
                        print(f" ({aliquota:.0f}%)", end="")
                    print(f" - {cedente}")
        
        print(f"\n🏛️ FATTURE CON CASSA PREVIDENZA: {stats['file_con_cassa_previdenza']}")
        if fatture_con_cassa:
            print(f"   Totale cassa: €{stats['totale_cassa_previdenza']:.2f}")
            print(f"   Tipi di cassa trovati:")
            tipi_cassa = {}
            for f in fatture_con_cassa:
                tipo = f.get('tipo_cassa', 'N/D')
                if tipo not in tipi_cassa:
                    tipi_cassa[tipo] = {'count': 0, 'totale': 0}
                tipi_cassa[tipo]['count'] += 1
                tipi_cassa[tipo]['totale'] += f['importo_cassa']
            
            for tipo, dati in sorted(tipi_cassa.items()):
                print(f"      • {tipo}: {dati['count']} fatture - €{dati['totale']:.2f}")
        
        if fatture_con_entrambe:
            print(f"\n🔄 FATTURE CON ENTRAMBE: {len(fatture_con_entrambe)}")
            if len(fatture_con_entrambe) > 0:
                print(f"   Prime {min(3, len(fatture_con_entrambe))} fatture:")
                for f in fatture_con_entrambe[:3]:
                    print(f"      • {f['numero']} - RIT: €{f['importo_ritenuta']:.2f} + CASSA: €{f['importo_cassa']:.2f}")
        
        # Mostra struttura cartelle create
        if stats.get('struttura_cartelle'):
            print(f"\n📂 Struttura cartelle create:")
            for folder, count in sorted(stats['struttura_cartelle'].items())[:10]:
                print(f"   └── {folder} ({count} file)")
            if len(stats['struttura_cartelle']) > 10:
                print(f"   └── ... e altre {len(stats['struttura_cartelle'])-10} cartelle")
        
        print(f"\n📄 Report salvati:")
        print(f"   • Generale: {report_path.name}")
        if fatture_con_ritenuta:
            print(f"   • Ritenute: fatture_con_ritenuta_{datetime.now().strftime('%Y%m%d')}.json")
        if fatture_con_cassa:
            print(f"   • Cassa: fatture_con_cassa_{datetime.now().strftime('%Y%m%d')}.json")
        print("=" * 60)


def main():
    """Funzione principale"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Estrae dati da fatture XML e crea file JSON mantenendo la struttura delle cartelle'
    )
    parser.add_argument(
        'input_dir',
        nargs='?',
        help='Directory contenente i file XML delle fatture'
    )
    parser.add_argument(
        'output_dir',
        nargs='?',
        help='Directory dove salvare i file JSON (default: input_dir)'
    )
    parser.add_argument(
        '--flat',
        action='store_true',
        help='Salva tutti i JSON in una singola cartella invece di mantenere la struttura'
    )
    parser.add_argument(
        '--ritenute',
        action='store_true',
        help='Processa SOLO fatture con ritenuta d\'acconto'
    )
    parser.add_argument(
        '--cassa',
        action='store_true',
        help='Processa SOLO fatture con cassa previdenza'
    )
    parser.add_argument(
        '--entrambe',
        action='store_true',
        help='Processa SOLO fatture con SIA ritenuta CHE cassa previdenza'
    )
    parser.add_argument(
        '--report',
        action='store_true',
        help='Genera report riepilogativo dettagliato'
    )
    
    args = parser.parse_args()
    
    # Se non specificato input, usa le directory di default
    if not args.input_dir:
        # Cerca nella struttura del xml_fatture_processor
        possible_dirs = [
            Path('aziende_processate'),
            Path('temp_download_ade'),
            Path('fatture_xml'),
            Path.cwd()
        ]
        
        for dir_path in possible_dirs:
            if dir_path.exists():
                args.input_dir = str(dir_path)
                print(f"📁 Uso directory trovata: {dir_path}")
                break
    
    # Se non specificato output, usa la stessa directory dell'input
    if not args.output_dir:
        args.output_dir = args.input_dir
        print(f"💾 Output nella stessa directory dell'input")
    
    # Gestione filtri
    filter_ritenute = args.ritenute or args.entrambe
    filter_cassa = args.cassa or args.entrambe
    
    # Crea estrattore
    extractor = FatturaJSONExtractor(args.input_dir, args.output_dir)
    
    print(f"\n🚀 ESTRATTORE JSON FATTURE v1.0")
    print(f"📂 Input: {extractor.input_dir}")
    print(f"💾 Output: {extractor.output_dir}")
    print(f"🗂️ Modalità: {'Flat (singola cartella)' if args.flat else 'Struttura preservata'}")
    
    if filter_ritenute or filter_cassa:
        print(f"🔍 FILTRI ATTIVI:")
        if args.entrambe:
            print(f"   ✓ Solo fatture con RITENUTA E CASSA PREVIDENZA")
        else:
            if args.ritenute:
                print(f"   ✓ Solo fatture con RITENUTA D'ACCONTO")
            if args.cassa:
                print(f"   ✓ Solo fatture con CASSA PREVIDENZA")
    
    print("=" * 60)
    
    # Processa directory
    stats = extractor.process_directory(
        preserve_structure=not args.flat,
        filter_ritenute=filter_ritenute,
        filter_cassa=filter_cassa
    )
    
    # Genera report se richiesto o se ci sono risultati
    if args.report or stats['file_processati'] > 0:
        extractor.generate_summary_report(stats, filter_ritenute, filter_cassa)


if __name__ == "__main__":
    main()