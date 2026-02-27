import requests
import json
import hashlib
import os
import base64
from datetime import datetime, timedelta
from pathlib import Path
import pickle
import logging
import re
import time
import zipfile
from collections import defaultdict

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ThreatIntelCollector:
    def __init__(self):
        """Otomatik Threat Intel Toplayıcı"""
        
        # GitHub token (otomatik olarak Actions'tan gelir)
        self.github_token = os.environ.get('GITHUB_TOKEN')
        
        # Telegram Anahtarları (GitHub Secrets'tan gelir)
        self.telegram_token = os.environ.get('TELEGRAM_TOKEN')
        self.telegram_chat_id = os.environ.get('TELEGRAM_CHAT_ID')
        
        # OTX API (GitHub Secrets'tan gelir - GÜVENLİK İÇİN HARDCODE EDİLMEDİ)
        self.otx_key = os.environ.get('OTX_API_KEY')
        
        # Veri klasörleri
        self.data_dir = Path("data")
        self.ioc_dir = Path("iocs")
        self.yara_dir = Path("yara_rules")
        self.report_dir = Path("weekly_reports")
        self.archive_dir = Path("monthly_archives")
        
        for dir_path in [self.data_dir, self.ioc_dir, self.yara_dir, self.report_dir, self.archive_dir]:
            dir_path.mkdir(exist_ok=True)
        
        # Hafıza (daha önce görülenler)
        self.seen_iocs = self.load_data("seen_iocs.pkl", set())
        self.seen_yara = self.load_data("seen_yara.pkl", set())
        self.stats = self.load_data("stats.json", {
            'total_iocs': 0,
            'total_yara': 0,
            'by_source': defaultdict(int),
            'by_type': defaultdict(int),
            'last_update': None,
            'runs': 0
        })
        
        # YARA kaynakları (GÜNCEL ve GÜVENİLİR)
        self.yara_sources = [
            {
                'name': 'Neo23x0 Signature Base',
                'url': 'https://api.github.com/repos/Neo23x0/signature-base/contents/yara',
                'branch': 'master',
                'active': True
            },
            {
                'name': 'YARA-Rules Project',
                'url': 'https://api.github.com/repos/Yara-Rules/rules/contents/',
                'branch': 'master',
                'active': True
            },
            # InQuest ve ESET repoları yapılarını değiştirdiği için geçici olarak devre dışı
            {
                'name': 'InQuest Awesome YARA',
                'url': 'https://api.github.com/repos/InQuest/awesome-yara/contents/rules',
                'branch': 'master',
                'active': False 
            },
            {
                'name': 'ESET Malware Research',
                'url': 'https://api.github.com/repos/eset/malware-research/contents/yara',
                'branch': 'master',
                'active': False
            },
            {
                'name': 'Intezer YARA',
                'url': 'https://api.github.com/repos/intezer/yara-rules/contents/',
                'branch': 'master',
                'active': True
            }
        ]
        logger.info("✅ Threat Intel Collector başlatıldı")
        logger.info(f"📊 Hafızada: {len(self.seen_iocs)} IOC, {len(self.seen_yara)} YARA")

    def send_telegram_message(self, message):
        """Telegram'a bildirim gönderir"""
        if not self.telegram_token or not self.telegram_chat_id:
            logger.warning("⚠️ Telegram token veya chat ID bulunamadı. Bildirim gönderilmeyecek.")
            return

        url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
        payload = {
            "chat_id": self.telegram_chat_id,
            "text": message,
            "parse_mode": "HTML"
        }
        
        try:
            response = requests.post(url, json=payload, timeout=15)
            if response.status_code == 200:
                logger.info("✅ Telegram bildirimi başarıyla gönderildi.")
            else:
                logger.error(f"❌ Telegram bildirimi başarısız! HTTP Kodu: {response.status_code} - Hata: {response.text}")
        except Exception as e:
            logger.error(f"❌ Telegram servisine bağlanırken hata oluştu: {e}")
    
    def load_data(self, filename, default):
        """Veri yükle"""
        filepath = self.data_dir / filename
        try:
            if filepath.exists():
                with open(filepath, 'rb') as f:
                    return pickle.load(f)
        except Exception as e:
            logger.error(f"❌ Veri yüklenirken hata: {e}")
        return default
    
    def save_data(self, filename, data):
        """Veri kaydet"""
        filepath = self.data_dir / filename
        try:
            with open(filepath, 'wb') as f:
                pickle.dump(data, f)
        except Exception as e:
            logger.error(f"❌ Veri kaydedilirken hata: {e}")
    
    def calculate_hash(self, content):
        """Hash hesapla (tekrar kontrolü için)"""
        return hashlib.sha256(str(content).encode()).hexdigest()
    
    def is_new_ioc(self, value, source):
        """Yeni IOC mi?"""
        hash_val = self.calculate_hash(f"{source}:{value}")
        if hash_val not in self.seen_iocs:
            self.seen_iocs.add(hash_val)
            self.stats['total_iocs'] += 1
            self.stats['by_source'][source] += 1
            return True
        return False
    
    def is_new_yara(self, name, content, source):
        """Yeni YARA kuralı mı?"""
        content_preview = content[:1000] if content else ""
        hash_val = self.calculate_hash(f"{source}:{name}:{content_preview}")
        if hash_val not in self.seen_yara:
            self.seen_yara.add(hash_val)
            self.stats['total_yara'] += 1
            self.stats['by_source'][f"{source}_YARA"] += 1
            return True
        return False
    
    def fetch_github_yara(self, source):
        """GitHub'dan YARA kurallarını çek"""
        try:
            headers = {}
            if self.github_token:
                headers['Authorization'] = f'token {self.github_token}'
            
            logger.info(f"🔍 {source['name']} kontrol ediliyor...")
            response = requests.get(source['url'], headers=headers, timeout=30)
            
            if response.status_code == 200:
                files = response.json()
                yara_files = []
                for f in files:
                    if isinstance(f, dict) and f.get('type') == 'file' and f['name'].endswith(('.yar', '.yara', '.rule')):
                        yara_files.append(f)
                
                logger.info(f"  📂 {len(yara_files)} YARA dosyası bulundu")
                
                new_rules = []
                for file in yara_files[:50]:
                    try:
                        content_response = requests.get(file['download_url'], timeout=30)
                        if content_response.status_code == 200:
                            content = content_response.text
                            
                            if self.is_new_yara(file['name'], content, source['name']):
                                rule_info = {
                                    'source': source['name'],
                                    'name': file['name'],
                                    'content': content,
                                    'path': file.get('path', ''),
                                    'url': file['html_url'],
                                    'size': file.get('size', 0),
                                    'collected_at': datetime.now().isoformat()
                                }
                                new_rules.append(rule_info)
                                logger.info(f"  ✅ Yeni: {file['name']}")
                    except Exception as e:
                        logger.error(f"  ❌ {file['name']} okunamadı: {e}")
                
                logger.info(f"  📥 {len(new_rules)} yeni YARA kuralı bulundu")
                return new_rules
            else:
                logger.error(f"❌ {source['name']} hatası: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"❌ {source['name']} bağlantı hatası: {e}")
            return []
    
    def fetch_alienvault_iocs(self):
        """AlienVault OTX'den IOC'leri al"""
        try:
            if not self.otx_key:
                logger.warning("⚠️ OTX API anahtarı yok, IOC çekilemiyor")
                return []
            
            url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
            headers = {"X-OTX-API-KEY": self.otx_key}
            params = {"limit": 10, "page": 1}
            
            logger.info("🔍 AlienVault OTX kontrol ediliyor...")
            response = requests.get(url, headers=headers, params=params, timeout=60)
            
            if response.status_code == 200:
                data = response.json()
                pulses = data.get('results', [])
                logger.info(f"  📂 {len(pulses)} pulse bulundu")
                
                new_iocs = []
                for pulse in pulses:
                    indicators = pulse.get('indicators', [])
                    for ioc in indicators[:5]:
                        ioc_value = ioc.get('indicator')
                        ioc_type = ioc.get('type', 'unknown')
                        
                        if ioc_value and self.is_new_ioc(ioc_value, 'AlienVault'):
                            ioc_info = {
                                'source': 'AlienVault OTX',
                                'pulse': pulse.get('name', 'Unknown'),
                                'type': ioc_type,
                                'value': ioc_value,
                                'description': pulse.get('description', '')[:200],
                                'tags': pulse.get('tags', []),
                                'created': pulse.get('created'),
                                'reference': f"https://otx.alienvault.com/pulse/{pulse.get('id')}"
                            }
                            new_iocs.append(ioc_info)
                
                logger.info(f"  📥 {len(new_iocs)} yeni IOC bulundu")
                return new_iocs
            else:
                logger.error(f"❌ AlienVault hatası: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"❌ AlienVault bağlantı hatası: {e}")
            return []
    
    def save_yara_rules(self, rules):
        """YARA kurallarını günlük klasöre kaydet"""
        if not rules:
            return []
        
        today = datetime.now().strftime('%Y-%m-%d')
        today_dir = self.yara_dir / today
        today_dir.mkdir(exist_ok=True)
        
        saved_files = []
        for rule in rules:
            try:
                safe_name = re.sub(r'[^\w\-_\.]', '_', rule['name'])
                if len(safe_name) > 100:
                    name_part = safe_name[:50]
                    hash_part = self.calculate_hash(safe_name)[:8]
                    safe_name = f"{name_part}_{hash_part}.yar"
                elif not safe_name.endswith(('.yar', '.yara')):
                    safe_name += '.yar'
                
                filepath = today_dir / safe_name
                
                header = f"""// ════════════════════════════════════════════════════════
// Kaynak    : {rule['source']}
// Kural     : {rule['name']}
// Toplanma  : {rule['collected_at']}
// Orijinal  : {rule['url']}
// ════════════════════════════════════════════════════════

"""
                with open(filepath, 'w', encoding='utf-8', errors='ignore') as f:
                    f.write(header + rule['content'])
                
                saved_files.append(str(filepath))
                logger.info(f"  💾 Kaydedildi: {filepath}")
            except Exception as e:
                logger.error(f"  ❌ {rule['name']} kaydedilemedi: {e}")
        
        return saved_files
    
    def save_iocs(self, iocs):
        """IOC'leri günlük klasöre kaydet"""
        if not iocs:
            return []
        
        today = datetime.now().strftime('%Y-%m-%d')
        today_dir = self.ioc_dir / today
        today_dir.mkdir(exist_ok=True)
        
        saved_files = []
        for ioc in iocs:
            try:
                ioc_type = ioc['type'].lower().replace(' ', '_')
                ioc_hash = self.calculate_hash(ioc['value'])[:8]
                filename = f"{ioc_type}_{ioc_hash}.json"
                filepath = today_dir / filename
                
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(ioc, f, indent=2, ensure_ascii=False)
                
                saved_files.append(str(filepath))
            except Exception as e:
                logger.error(f"  ❌ IOC kaydedilemedi: {e}")
        
        logger.info(f"  💾 {len(saved_files)} IOC kaydedildi")
        return saved_files
    
    def create_weekly_report(self):
        """Haftalık rapor oluştur"""
        today = datetime.now()
        
        if today.weekday() == 0:
            week_num = today.strftime('%W')
            year = today.strftime('%Y')
            
            report_file = self.report_dir / f"week-{week_num}-{year}.md"
            
            week_iocs = 0
            week_yara = 0
            
            for i in range(7):
                date = (today - timedelta(days=i)).strftime('%Y-%m-%d')
                ioc_day_dir = self.ioc_dir / date
                yara_day_dir = self.yara_dir / date
                
                if ioc_day_dir.exists():
                    week_iocs += len(list(ioc_day_dir.glob("*.json")))
                if yara_day_dir.exists():
                    week_yara += len(list(yara_day_dir.glob("*.yar*")))
            
            report = "# 📊 Haftalık Tehdit İstihbaratı Raporu\n"
            report += f"**Hafta:** {week_num} - {year}\n"
            report += f"**Tarih:** {today.strftime('%d.%m.%Y')}\n\n"
            report += "## 📈 Özet İstatistikler\n"
            report += f"- **Toplam IOC:** {self.stats['total_iocs']}\n"
            report += f"- **Toplam YARA Kuralı:** {self.stats['total_yara']}\n"
            report += f"- **Bu Hafta Eklenen IOC:** {week_iocs}\n"
            report += f"- **Bu Hafta Eklenen YARA:** {week_yara}\n"
            report += f"- **Çalışma Sayısı:** {self.stats['runs']}\n\n"
            report += "## 🔍 Kaynak Dağılımı\n"
            report += "```json\n"
            report += json.dumps(dict(self.stats['by_source']), indent=2, ensure_ascii=False)
            report += "\n```\n\n"
            report += "## 🎯 Öne Çıkan Yeni Kurallar\n"
            
            for i in range(7):
                date = (today - timedelta(days=i)).strftime('%Y-%m-%d')
                yara_day_dir = self.yara_dir / date
                if yara_day_dir.exists():
                    report += f"\n### {date}\n"
                    yara_files = list(yara_day_dir.glob("*.yar*"))[:10]
                    for yar_file in yara_files:
                        report += f"- [{yar_file.name}](../yara_rules/{date}/{yar_file.name})\n"
            
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(report)
            
            logger.info(f"📊 Haftalık rapor oluşturuldu: {report_file}")
    
    def create_monthly_archive(self):
        """Aylık arşiv oluştur"""
        today = datetime.now()
        
        if today.day == 1:
            last_month = today - timedelta(days=1)
            month = last_month.strftime('%Y-%m')
            
            archive_name = self.archive_dir / f"{month}.zip"
            
            with zipfile.ZipFile(archive_name, 'w', zipfile.ZIP_DEFLATED) as zipf:
                files_added = 0
                for i in range(30):
                    date = (today - timedelta(days=i+1)).strftime('%Y-%m-%d')
                    if date.startswith(month):
                        ioc_day_dir = self.ioc_dir / date
                        yara_day_dir = self.yara_dir / date
                        
                        if ioc_day_dir.exists():
                            for file in ioc_day_dir.glob("*"):
                                zipf.write(file, f"iocs/{date}/{file.name}")
                                files_added += 1
                        
                        if yara_day_dir.exists():
                            for file in yara_day_dir.glob("*"):
                                zipf.write(file, f"yara/{date}/{file.name}")
                                files_added += 1
                
                logger.info(f"📦 Aylık arşiv oluşturuldu: {archive_name} ({files_added} dosya)")
    
    def update_readme(self):
        """README.md'yi otomatik güncelle"""
        try:
            week_iocs = 0
            week_yara = 0
            today = datetime.now()
            
            for i in range(7):
                date = (today - timedelta(days=i)).strftime('%Y-%m-%d')
                ioc_day_dir = self.ioc_dir / date
                yara_day_dir = self.yara_dir / date
                
                if ioc_day_dir.exists():
                    week_iocs += len(list(ioc_day_dir.glob("*.json")))
                if yara_day_dir.exists():
                    week_yara += len(list(yara_day_dir.glob("*.yar*")))
            
            yara_sources_list = "\n".join([f"- **{s['name']}**" for s in self.yara_sources if s.get('active', True)])
            
            readme_content = f"""# 🛡️ Threat Intelligence Auto Collection

Bu repository **otomatik olarak** her 6 saatte bir güncellenir. Yeni çıkan IOC'leri ve YARA kurallarını toplar ve düzenler.

## 📊 Güncel İstatistikler
- **Toplam IOC:** {self.stats['total_iocs']}
- **Toplam YARA Kuralı:** {self.stats['total_yara']}
- **Son 7 Gün:** +{week_iocs} IOC, +{week_yara} YARA
- **Son Güncelleme:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- **Çalışma Sayısı:** {self.stats['runs']}

## 📁 Klasör Yapısı
- `/iocs/`: Günlük toplanan IOC'ler
- `/yara_rules/`: Toplanan YARA kuralları
- `/weekly_reports/`: Otomatik oluşturulan haftalık özetler
- `/monthly_archives/`: Zip formatında aylık yedekler

## 🔍 Takip Edilen Kaynaklar
{yara_sources_list}
"""
            with open("README.md", "w", encoding="utf-8") as f:
                f.write(readme_content)
                
            logger.info("✅ README.md başarıyla güncellendi.")
        except Exception as e:
            logger.error(f"❌ README güncellenirken hata: {e}")

    def run(self):
        """Tüm toplama ve arşivleme sürecini başlatır"""
        logger.info("🚀 Toplama süreci başlatılıyor...")
        self.stats['runs'] += 1
        
        new_iocs_count = 0
        new_yara_count = 0
        
        # 1. IOC'leri topla
        iocs = self.fetch_alienvault_iocs()
        saved_iocs = self.save_iocs(iocs)
        new_iocs_count += len(saved_iocs) if saved_iocs else 0
        
        # 2. YARA Kurallarını topla
        for source in self.yara_sources:
            if source.get('active', True):
                rules = self.fetch_github_yara(source)
                saved_rules = self.save_yara_rules(rules)
                new_yara_count += len(saved_rules) if saved_rules else 0
                
        # 3. İstatistikleri ve tracker verilerini güncelle
        self.stats['last_update'] = datetime.now().isoformat()
        self.save_data("stats.json", self.stats)
        self.save_data("seen_iocs.pkl", self.seen_iocs)
        self.save_data("seen_yara.pkl", self.seen_yara)
        
        # 4. Raporlama
        self.create_weekly_report()
        self.create_monthly_archive()
        self.update_readme()
        
        # 5. Telegram'a Özet Bildirim Gönder
        summary_msg = (
            f"🤖 <b>Threat Intel Bot Çalıştı</b>\n\n"
            f"📥 <b>Yeni Eklenenler:</b>\n"
            f"🔸 Yeni IOC: <b>{new_iocs_count}</b>\n"
            f"🔸 Yeni YARA: <b>{new_yara_count}</b>\n\n"
            f"📊 <b>Genel Toplam:</b>\n"
            f"🔹 Toplam IOC: {self.stats['total_iocs']}\n"
            f"🔹 Toplam YARA: {self.stats['total_yara']}"
        )
        self.send_telegram_message(summary_msg)
        
        logger.info("🎉 Tüm işlemler başarıyla tamamlandı!")

if __name__ == "__main__":
    collector = ThreatIntelCollector()
    collector.run()
