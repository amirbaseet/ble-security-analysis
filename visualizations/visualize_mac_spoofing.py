#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MAC Spoofing Analysis Visualization
macSpoof.py analiz sonuçlarını görselleştiren script
"""

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import sqlite3
import numpy as np
from datetime import datetime
import warnings
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from config import DB_PATH, FOTOS_DIR, DOCS_DIR
from matplotlib.dates import DateFormatter, HourLocator



warnings.filterwarnings('ignore')

# Turkish font support for matplotlib
plt.rcParams['font.family'] = ['DejaVu Sans']

class MacSpoofingVisualizer:
    def __init__(self, db_path=DB_PATH, docs_path=DOCS_DIR,png_path=FOTOS_DIR):
        self.db_path = db_path
        self.docs_path = docs_path+'/'
        self.png_path = png_path+'/'
        self.raw_data = None
        self.fingerprint_changes = None
        self.alerts = None
        self.top_uuids = None
        self.top_manufacturers = None
        
        # Color palette
        self.colors = {
            'primary': '#1f77b4',
            'danger': '#d62728',
            'warning': '#ff7f0e', 
            'success': '#2ca02c',
            'info': '#17becf',
            'purple': '#9467bd'
        }
        
    def load_data(self):
        """Veritabanından ve CSV dosyalarından verileri yükler"""
        print("📊 MAC Spoofing analiz verileri yükleniyor...")
        
        # Ana veriyi veritabanından yükle
        conn = sqlite3.connect(self.db_path)
        self.raw_data = pd.read_sql_query("""
            SELECT 
                BLEPacket.id,
                BLEPacket.timestamp,
                BLEPacket.dmac,
                BLEPacket.smac,
                BLEPacket.company_id,
                BLEPacket.manufacturer_data,
                BLEPacketUUID.uuid_type,
                BLEPacketUUID.uuid
            FROM BLEPacket
            LEFT JOIN BLEPacketUUID ON BLEPacket.id = BLEPacketUUID.ble_packet_id
        """, conn)
        conn.close()
        
        # Timestamp dönüşümü
        self.raw_data['timestamp'] = pd.to_datetime(self.raw_data['timestamp'], errors='coerce')
        
        # CSV dosyalarını yükle
        try:
            fingerprint_file = os.path.join(self.docs_path, "Fingerprint_Change_Events.csv")
            if os.path.exists(fingerprint_file):
                self.fingerprint_changes = pd.read_csv(fingerprint_file)
                self.fingerprint_changes['timestamp'] = pd.to_datetime(self.fingerprint_changes['timestamp'])
                print(f"✅ Fingerprint değişiklikleri: {len(self.fingerprint_changes)} kayıt")
            
            alerts_file = os.path.join(self.docs_path, "MacSpoofingAlerts.csv")
            if os.path.exists(alerts_file):
                self.alerts = pd.read_csv(alerts_file)
                print(f"✅ MAC Spoofing alert'leri: {len(self.alerts)} kayıt")
                
                # DEBUG: Veri strukturunu yazdır
                print(f"🔍 DEBUG - Alert kolonları: {list(self.alerts.columns)}")
                print(f"🔍 DEBUG - İlk 3 satır:")
                print(self.alerts.head(3))
                
            else:
                print("⚠️ MacSpoofingAlerts.csv bulunamadı")
            
            uuid_file = os.path.join(self.docs_path, "Top_UUIDs.csv")
            if os.path.exists(uuid_file):
                self.top_uuids = pd.read_csv(uuid_file)
                print(f"✅ Top UUID'ler: {len(self.top_uuids)} kayıt")
            
            manufacturer_file = os.path.join(self.docs_path, "Top_ManufacturerData.csv")
            if os.path.exists(manufacturer_file):
                self.top_manufacturers = pd.read_csv(manufacturer_file)
                print(f"✅ Top Manufacturer Data: {len(self.top_manufacturers)} kayıt")
                
        except Exception as e:
            print(f"⚠️ CSV dosyaları yüklenirken hata: {e}")
        
        print("✅ Veri yükleme tamamlandı!")
    
    def create_fingerprint_analysis(self):
        """Fingerprint analizi grafikleri"""
        if self.fingerprint_changes is None or len(self.fingerprint_changes) == 0:
            print("⚠️ Fingerprint değişiklik verisi bulunamadı")
            return
            
        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        
        try:
            # 1. Zaman içinde fingerprint değişiklikleri
            hourly_changes = self.fingerprint_changes.set_index('timestamp').resample('1H').size()
            
            # Son 48 saati göster (çok uzun olursa)
            if len(hourly_changes) > 48:
                hourly_changes = hourly_changes.tail(48)
            
            axes[0,0].plot(hourly_changes.index, hourly_changes.values, 
                          color=self.colors['danger'], linewidth=2, marker='o', markersize=4)
            axes[0,0].set_title('🕐 Saatlik Fingerprint Değişiklikleri (Son 48 Saat)', fontsize=14, fontweight='bold')
            axes[0,0].set_xlabel('Zaman')
            axes[0,0].set_ylabel('Değişiklik Sayısı')
            
            # X-axis formatını düzenle
            axes[0,0].xaxis.set_major_formatter(DateFormatter('%m-%d %H:%M'))
            axes[0,0].xaxis.set_major_locator(HourLocator(interval=6))  # Her 6 saatte bir göster
            axes[0,0].tick_params(axis='x', rotation=45)
            axes[0,0].grid(True, alpha=0.3)
            
            # 2. MAC adresi başına fingerprint değişiklik sayısı
            mac_changes = self.fingerprint_changes['smac'].value_counts().head(10)
            axes[0,1].barh(range(len(mac_changes)), mac_changes.values, color=self.colors['warning'])
            axes[0,1].set_yticks(range(len(mac_changes)))
            axes[0,1].set_yticklabels([mac[:15] + '...' if len(mac) > 15 else mac for mac in mac_changes.index])
            axes[0,1].set_title('🔝 En Çok Fingerprint Değiştiren MAC\'ler', fontweight='bold')
            axes[0,1].set_xlabel('Değişiklik Sayısı')
            
            # 3. Fingerprint değişiklik türleri analizi
            if len(self.fingerprint_changes) > 0:
                # Günlük değişiklik dağılımı
                daily_changes = self.fingerprint_changes.set_index('timestamp').resample('D').size()
                
                # Eğer çok fazla gün varsa, son 30 günü göster
                if len(daily_changes) > 30:
                    daily_changes = daily_changes.tail(30)
                
                # X-axis için tarih etiketleri hazırla
                dates = daily_changes.index.strftime('%m-%d')  # MM-DD formatında
                
                axes[1,0].bar(range(len(daily_changes)), daily_changes.values, color=self.colors['info'], alpha=0.8, edgecolor='black')
                axes[1,0].set_title('📅 Günlük Fingerprint Değişiklikleri (Son 30 Gün)', fontweight='bold')
                axes[1,0].set_xlabel('Tarih (Ay-Gün)')
                axes[1,0].set_ylabel('Değişiklik Sayısı')
                
                # X-axis etiketlerini ayarla
                axes[1,0].set_xticks(range(len(daily_changes)))
                axes[1,0].set_xticklabels(dates, rotation=45, ha='right')
                axes[1,0].grid(True, alpha=0.3)
                
                # Değer etiketlerini çubukların üzerine ekle
                for i, v in enumerate(daily_changes.values):
                    if v > 0:  # Sadece 0'dan büyük değerleri göster
                        axes[1,0].text(i, v + max(daily_changes.values) * 0.01, str(int(v)), 
                                      ha='center', va='bottom', fontsize=9)
            
            # 4. Unique fingerprint sayısı dağılımı
            if self.alerts is not None and 'unique_fingerprints' in self.alerts.columns:
                fingerprint_dist = self.alerts['unique_fingerprints'].value_counts().sort_index()
                axes[1,1].bar(fingerprint_dist.index, fingerprint_dist.values, color=self.colors['purple'])
                axes[1,1].set_title('📊 MAC Başına Unique Fingerprint Dağılımı', fontweight='bold')
                axes[1,1].set_xlabel('Unique Fingerprint Sayısı')
                axes[1,1].set_ylabel('MAC Sayısı')
                axes[1,1].grid(True, alpha=0.3)
            
            plt.tight_layout()
            plt.savefig(f'{self.png_path}mac_spoofing_fingerprint_analysis.png', dpi=300, bbox_inches='tight')
            print("✅ Fingerprint analizi grafiği kaydedildi")
            plt.show()
            
        except Exception as e:
            print(f"❌ Fingerprint analizi grafiği oluşturulamadı: {e}")
    
    def create_anomaly_dashboard(self):
        """Anomali dashboard'u"""
        if self.alerts is None or len(self.alerts) == 0:
            print("⚠️ Alert verisi bulunamadı")
            return
            
        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        
        try:
            # 1. Anomali türleri dağılımı
            anomaly_types = []
            if 'fingerprint_anomaly' in self.alerts.columns:
                fp_count = self.alerts['fingerprint_anomaly'].sum()
                anomaly_types.append(('Fingerprint Anomali', fp_count))
            if 'dmac_anomaly' in self.alerts.columns:
                dmac_count = self.alerts['dmac_anomaly'].sum()
                anomaly_types.append(('DMAC Anomali', dmac_count))
            
            if anomaly_types:
                labels, values = zip(*anomaly_types)
                axes[0,0].pie(values, labels=labels, autopct='%1.1f%%', 
                             colors=[self.colors['danger'], self.colors['warning']])
                axes[0,0].set_title('🚨 Anomali Türleri Dağılımı', fontweight='bold')
            
            # 2. Paket sayısı vs anomali ilişkisi
            if 'packet_count' in self.alerts.columns:
                packet_counts = self.alerts['packet_count']
                axes[0,1].hist(packet_counts, bins=20, color=self.colors['info'], alpha=0.7, edgecolor='black')
                axes[0,1].set_title('📦 Anomalili MAC\'lerin Paket Sayısı Dağılımı', fontweight='bold')
                axes[0,1].set_xlabel('Paket Sayısı')
                axes[0,1].set_ylabel('MAC Sayısı')
                axes[0,1].grid(True, alpha=0.3)
            
            # 3. Top anomalili MAC'ler
            if 'packet_count' in self.alerts.columns:
                top_anomalies = self.alerts.nlargest(10, 'packet_count')
                axes[1,0].barh(range(len(top_anomalies)), top_anomalies['packet_count'].values, 
                              color=self.colors['danger'])
                axes[1,0].set_yticks(range(len(top_anomalies)))
                mac_labels = [mac[:15] + '...' if len(str(mac)) > 15 else str(mac) 
                             for mac in top_anomalies['smac'].values]
                axes[1,0].set_yticklabels(mac_labels)
                axes[1,0].set_title('⚠️ En Yüksek Trafikli Anomalili MAC\'ler', fontweight='bold')
                axes[1,0].set_xlabel('Paket Sayısı')
            
            # 4. Anomali istatistikleri özet - FIX: F-string formatını düzelt
            total_anomalies = len(self.alerts)
            avg_packets = self.alerts['packet_count'].mean() if 'packet_count' in self.alerts.columns else None
            max_packets = self.alerts['packet_count'].max() if 'packet_count' in self.alerts.columns else None
            fp_anomalies = self.alerts['fingerprint_anomaly'].sum() if 'fingerprint_anomaly' in self.alerts.columns else None
            dmac_anomalies = self.alerts['dmac_anomaly'].sum() if 'dmac_anomaly' in self.alerts.columns else None
            
            # Format değerlerini hazırla
            avg_packets_str = f"{avg_packets:.1f}" if avg_packets is not None else 'N/A'
            max_packets_str = str(max_packets) if max_packets is not None else 'N/A'
            fp_anomalies_str = str(fp_anomalies) if fp_anomalies is not None else 'N/A'
            dmac_anomalies_str = str(dmac_anomalies) if dmac_anomalies is not None else 'N/A'
            
            stats_text = f"""
📊 ANOMALI ÖZETİ

Toplam Anomalili MAC: {total_anomalies}
Ortalama Paket Sayısı: {avg_packets_str}
Maksimum Paket Sayısı: {max_packets_str}
Fingerprint Anomali: {fp_anomalies_str}
DMAC Anomali: {dmac_anomalies_str}
            """
            axes[1,1].text(0.1, 0.9, stats_text, transform=axes[1,1].transAxes, 
                           fontsize=12, verticalalignment='top', fontfamily='monospace')
            axes[1,1].set_title('📋 Anomali İstatistikleri', fontweight='bold')
            axes[1,1].axis('off')
            
            plt.tight_layout()
            plt.savefig(f'{self.png_path}/mac_spoofing_anomaly_dashboard.png', dpi=300, bbox_inches='tight')
            print("✅ Anomali dashboard grafiği kaydedildi")
            plt.show()
            
        except Exception as e:
            print(f"❌ Anomali dashboard grafiği oluşturulamadı: {e}")
    
    def create_pattern_analysis(self):
        """Pattern analizi grafikleri"""
        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        
        try:
            # 1. En çok kullanılan UUID'ler
            if self.top_uuids is not None and len(self.top_uuids) > 0:
                top_10_uuids = self.top_uuids.head(10)
                axes[0,0].barh(range(len(top_10_uuids)), top_10_uuids['count'].values, 
                              color=self.colors['success'])
                axes[0,0].set_yticks(range(len(top_10_uuids)))
                uuid_labels = [uuid[:20] + '...' if len(str(uuid)) > 20 else str(uuid) 
                              for uuid in top_10_uuids['uuid'].values]
                axes[0,0].set_yticklabels(uuid_labels)
                axes[0,0].set_title('🔍 En Çok Kullanılan UUID\'ler', fontweight='bold')
                axes[0,0].set_xlabel('Kullanım Sayısı')
            
            # 2. En çok kullanılan Manufacturer Data
            if self.top_manufacturers is not None and len(self.top_manufacturers) > 0:
                top_10_manufacturers = self.top_manufacturers.head(10)
                axes[0,1].barh(range(len(top_10_manufacturers)), top_10_manufacturers['count'].values, 
                              color=self.colors['primary'])
                axes[0,1].set_yticks(range(len(top_10_manufacturers)))
                mfg_labels = [mfg[:20] + '...' if len(str(mfg)) > 20 else str(mfg) 
                             for mfg in top_10_manufacturers['manufacturer_data'].values]
                axes[0,1].set_yticklabels(mfg_labels)
                axes[0,1].set_title('🏭 En Çok Kullanılan Manufacturer Data', fontweight='bold')
                axes[0,1].set_xlabel('Kullanım Sayısı')
            
            # 3. Company ID dağılımı (raw_data'dan)
            if self.raw_data is not None and 'company_id' in self.raw_data.columns:
                company_counts = self.raw_data['company_id'].value_counts().head(10)
                if len(company_counts) > 0:
                    axes[1,0].bar(range(len(company_counts)), company_counts.values, 
                                 color=self.colors['warning'])
                    axes[1,0].set_xticks(range(len(company_counts)))
                    axes[1,0].set_xticklabels([str(cid)[:10] + '...' if len(str(cid)) > 10 else str(cid) 
                                              for cid in company_counts.index], rotation=45)
                    axes[1,0].set_title('🏢 Company ID Dağılımı', fontweight='bold')
                    axes[1,0].set_ylabel('Kullanım Sayısı')
            
            # 4. UUID türleri dağılımı
            if self.raw_data is not None and 'uuid_type' in self.raw_data.columns:
                uuid_type_counts = self.raw_data['uuid_type'].value_counts()
                if len(uuid_type_counts) > 0:
                    axes[1,1].pie(uuid_type_counts.values, labels=uuid_type_counts.index, 
                                 autopct='%1.1f%%', colors=[self.colors['info'], self.colors['purple'], self.colors['success']])
                    axes[1,1].set_title('🔢 UUID Türleri Dağılımı', fontweight='bold')
            
            plt.tight_layout()
            plt.savefig(f'{self.png_path}mac_spoofing_pattern_analysis.png', dpi=300, bbox_inches='tight')
            print("✅ Pattern analizi grafiği kaydedildi")
            plt.show()
            
        except Exception as e:
            print(f"❌ Pattern analizi grafiği oluşturulamadı: {e}")
    
    def create_summary_report(self):
        """Özet rapor dosyası oluştur"""
        try:
            summary = {
                '🔍 MAC SPOOFING ANALİZ ÖZETİ': {
                    'Toplam BLE Paketi': len(self.raw_data) if self.raw_data is not None else 'N/A',
                    'Unique MAC Adresi': self.raw_data['smac'].nunique() if self.raw_data is not None else 'N/A',
                    'Fingerprint Değişiklikleri': len(self.fingerprint_changes) if self.fingerprint_changes is not None else 'N/A',
                    'Anomalili MAC Sayısı': len(self.alerts) if self.alerts is not None else 'N/A',
                    'Analiz Tarihi': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                },
                '🚨 ANOMALİ İSTATİSTİKLERİ': {},
                '📊 PATTERN İSTATİSTİKLERİ': {}
            }
            
            # Anomali istatistikleri
            if self.alerts is not None:
                if 'fingerprint_anomaly' in self.alerts.columns:
                    summary['🚨 ANOMALİ İSTATİSTİKLERİ']['Fingerprint Anomali'] = int(self.alerts['fingerprint_anomaly'].sum())
                if 'dmac_anomaly' in self.alerts.columns:
                    summary['🚨 ANOMALİ İSTATİSTİKLERİ']['DMAC Anomali'] = int(self.alerts['dmac_anomaly'].sum())
                if 'packet_count' in self.alerts.columns:
                    summary['🚨 ANOMALİ İSTATİSTİKLERİ']['Ortalama Paket Sayısı'] = f"{self.alerts['packet_count'].mean():.1f}"
            
            # Pattern istatistikleri
            if self.top_uuids is not None:
                summary['📊 PATTERN İSTATİSTİKLERİ']['Farklı UUID Sayısı'] = len(self.top_uuids)
            if self.top_manufacturers is not None:
                summary['📊 PATTERN İSTATİSTİKLERİ']['Farklı Manufacturer Data Sayısı'] = len(self.top_manufacturers)
            
            # Raporu dosyaya kaydet
            with open(f'{self.docs_path}mac_spoofing_summary.txt', 'w', encoding='utf-8') as f:
                f.write("=" * 60 + "\n")
                f.write("MAC SPOOFING ANALİZ RAPORU\n")
                f.write("=" * 60 + "\n\n")
                
                for category, items in summary.items():
                    f.write(f"{category}\n")
                    f.write("-" * 40 + "\n")
                    for key, value in items.items():
                        f.write(f"{key}: {value}\n")
                    f.write("\n")
            
            print("📋 MAC Spoofing özet raporu kaydedildi!")
            
        except Exception as e:
            print(f"❌ Özet rapor oluşturulamadı: {e}")
    
    def generate_all_visualizations(self):
        """Tüm görselleştirmeleri oluştur"""
        print("🎨 MAC Spoofing Analizi Görselleştirme Başlatılıyor...\n")
        
        # Verileri yükle
        self.load_data()
        
        if self.raw_data is None or len(self.raw_data) == 0:
            print("❌ Veri bulunamadı! Görselleştirme durduruldu.")
            return
        
        # Grafikleri oluştur
        print("\n📊 Fingerprint analizi grafikleri oluşturuluyor...")
        self.create_fingerprint_analysis()
        
        print("\n🚨 Anomali dashboard oluşturuluyor...")
        self.create_anomaly_dashboard()
        
        print("\n🔍 Pattern analizi grafikleri oluşturuluyor...")
        self.create_pattern_analysis()
        
        print("\n📋 Özet rapor oluşturuluyor...")
        self.create_summary_report()
        
        print("\n🎉 MAC Spoofing görselleştirmeleri tamamlandı!")
        print(f"📁 Dosyalar kaydedildi: {self.docs_path}")
        print("\n📋 Oluşturulan dosyalar:")
        print("   • mac_spoofing_fingerprint_analysis.png - Fingerprint analizi")
        print("   • mac_spoofing_anomaly_dashboard.png - Anomali dashboard")
        print("   • mac_spoofing_pattern_analysis.png - Pattern analizi")
        print("   • mac_spoofing_summary.txt - Özet rapor")

if __name__ == "__main__":
    # Görselleştirici oluştur ve çalıştır
    visualizer = MacSpoofingVisualizer()
    visualizer.generate_all_visualizations() 