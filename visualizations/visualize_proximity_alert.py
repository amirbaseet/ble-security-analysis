#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Proximity Alert Analysis Visualization
proximityAlert.py analiz sonuçlarını görselleştiren script
"""

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import sqlite3
import numpy as np
from datetime import datetime, timedelta
import warnings
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from config import DB_PATH, DOCS_DIR, FOTOS_DIR


warnings.filterwarnings('ignore')

# Turkish font support for matplotlib
plt.rcParams['font.family'] = ['DejaVu Sans']

class ProximityAlertVisualizer:
    def __init__(self, db_path=DB_PATH, docs_path=DOCS_DIR,png_path=FOTOS_DIR):
        self.db_path = db_path
        self.docs_path = docs_path+'/'
        self.png_path = png_path+'/'
        self.raw_distance_data = None
        self.proximity_alerts = None
        
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
        print("📊 Proximity Alert analiz verileri yükleniyor...")
        
        # Ana mesafe verilerini veritabanından yükle
        conn = sqlite3.connect(self.db_path)
        self.raw_distance_data = pd.read_sql_query("""
            SELECT timestamp, smac, dmac, distance, rssi
            FROM BLEPacket
            WHERE distance IS NOT NULL
            ORDER BY smac, timestamp
        """, conn)
        conn.close()
        
        # Timestamp dönüşümü
        self.raw_distance_data['timestamp'] = pd.to_datetime(self.raw_distance_data['timestamp'], format='mixed', errors='coerce')
        self.raw_distance_data['smac'] = self.raw_distance_data['smac'].str.lower()
        
        print(f"✅ Ham mesafe verileri: {len(self.raw_distance_data)} kayıt")
        
        # Proximity alert verilerini yükle
        try:
            alerts_file = os.path.join(self.docs_path, "ProximityAnomalyAlerts.csv")
            if os.path.exists(alerts_file):
                self.proximity_alerts = pd.read_csv(alerts_file)
                if 'timestamp_1' in self.proximity_alerts.columns:
                    self.proximity_alerts['timestamp_1'] = pd.to_datetime(self.proximity_alerts['timestamp_1'])
                if 'timestamp_2' in self.proximity_alerts.columns:
                    self.proximity_alerts['timestamp_2'] = pd.to_datetime(self.proximity_alerts['timestamp_2'])
                print(f"✅ Proximity alert'leri: {len(self.proximity_alerts)} kayıt")
            else:
                print("⚠️ ProximityAnomalyAlerts.csv bulunamadı")
                
        except Exception as e:
            print(f"⚠️ Proximity alert verileri yüklenirken hata: {e}")
        
        print("✅ Veri yükleme tamamlandı!")
    
    def create_distance_analysis(self):
        """Mesafe analizi grafikleri"""
        if self.raw_distance_data is None or len(self.raw_distance_data) == 0:
            print("⚠️ Mesafe verisi bulunamadı")
            return
            
        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        
        try:
            # 1. Mesafe dağılımı histogram
            distances = self.raw_distance_data['distance']
            axes[0,0].hist(distances, bins=50, color=self.colors['info'], alpha=0.7, edgecolor='black')
            axes[0,0].set_title('📏 BLE Cihaz Mesafe Dağılımı', fontsize=14, fontweight='bold')
            axes[0,0].set_xlabel('Mesafe (metre)')
            axes[0,0].set_ylabel('Frekans')
            axes[0,0].grid(True, alpha=0.3)
            axes[0,0].axvline(distances.mean(), color=self.colors['danger'], linestyle='--', 
                             label=f'Ortalama: {distances.mean():.1f}m')
            axes[0,0].legend()
            
            # 2. MAC adresi başına ortalama mesafe
            mac_avg_distance = self.raw_distance_data.groupby('smac')['distance'].agg(['mean', 'std', 'count']).reset_index()
            mac_avg_distance = mac_avg_distance.sort_values('mean', ascending=False).head(15)
            
            y_pos = range(len(mac_avg_distance))
            axes[0,1].barh(y_pos, mac_avg_distance['mean'].values, color=self.colors['primary'])
            axes[0,1].set_yticks(y_pos)
            axes[0,1].set_yticklabels([mac[:15] + '...' if len(mac) > 15 else mac 
                                      for mac in mac_avg_distance['smac'].values])
            axes[0,1].set_title('🔝 MAC Başına Ortalama Mesafe (Top 15)', fontweight='bold')
            axes[0,1].set_xlabel('Ortalama Mesafe (m)')
            
            # 3. Zaman içinde mesafe değişimi
            if len(self.raw_distance_data) > 100:
                # En aktif MAC'i seç
                most_active_mac = self.raw_distance_data['smac'].value_counts().index[0]
                mac_data = self.raw_distance_data[self.raw_distance_data['smac'] == most_active_mac].sort_values('timestamp')
                
                if len(mac_data) > 1:
                    axes[1,0].plot(mac_data['timestamp'], mac_data['distance'], 
                                  color=self.colors['success'], linewidth=1.5, marker='o', markersize=3)
                    axes[1,0].set_title(f'📈 Mesafe Değişimi - {most_active_mac[:20]}...', fontweight='bold')
                    axes[1,0].set_xlabel('Zaman')
                    axes[1,0].set_ylabel('Mesafe (m)')
                    axes[1,0].tick_params(axis='x', rotation=45)
                    axes[1,0].grid(True, alpha=0.3)
            
            # 4. RSSI vs Mesafe ilişkisi
            sample_data = self.raw_distance_data.sample(min(1000, len(self.raw_distance_data)))  # Performance için örnekleme
            axes[1,1].scatter(sample_data['rssi'], sample_data['distance'], 
                             alpha=0.6, color=self.colors['warning'], s=20)
            axes[1,1].set_title('📶 RSSI vs Mesafe İlişkisi', fontweight='bold')
            axes[1,1].set_xlabel('RSSI (dBm)')
            axes[1,1].set_ylabel('Mesafe (m)')
            axes[1,1].grid(True, alpha=0.3)
            
            plt.tight_layout()
            plt.savefig(f'{self.png_path}proximity_distance_analysis.png', dpi=300, bbox_inches='tight')
            print("✅ Mesafe analizi grafiği kaydedildi")
            plt.show()
            
        except Exception as e:
            print(f"❌ Mesafe analizi grafiği oluşturulamadı: {e}")
    
    def create_anomaly_dashboard(self):
        """Proximity anomaly dashboard'u"""
        if self.proximity_alerts is None or len(self.proximity_alerts) == 0:
            # Anomaly verisi olmadığında pozitif güvenlik mesajı göster
            fig, axes = plt.subplots(2, 2, figsize=(16, 12))
            
            # Her grafik alanına pozitif mesaj
            messages = [
                '🛡️ Mükemmel!\n\nProximity anomaly tespit edilmedi\n\nTüm mesafe değişimleri normal',
                '✅ Güvenli Ağ!\n\nMAC adreslerinde\nanormal yaklaşma yok',
                '📊 İdeal Durum!\n\nZaman içinde\nhiç anomaly yok',
                '🎯 Sağlıklı İletişim!\n\nTüm mesafe değişimleri\nbeklenen aralıkta'
            ]
            
            for i, (ax, msg) in enumerate(zip(axes.flat, messages)):
                ax.text(0.5, 0.5, msg, horizontalalignment='center', verticalalignment='center',
                       transform=ax.transAxes, fontsize=14, fontweight='bold',
                       bbox=dict(boxstyle="round,pad=0.3", facecolor=self.colors['success'], alpha=0.7))
                ax.set_xlim(0, 1)
                ax.set_ylim(0, 1)
                ax.axis('off')
            
            titles = [
                '🚨 Mesafe Sıçrama Dağılımı',
                '📱 En Çok Anomaly Üreten MAC\'ler', 
                '⏰ Saatlik Proximity Anomaly Sayısı',
                '⏰ Zaman Penceresi vs Mesafe Sıçrama'
            ]
            
            for ax, title in zip(axes.flat, titles):
                ax.set_title(title, fontsize=14, fontweight='bold')
            
            plt.tight_layout()
            plt.savefig(f'{self.png_path}proximity_anomaly_dashboard.png', dpi=300, bbox_inches='tight')
            print("✅ Proximity anomaly dashboard kaydedildi (güvenlik durumu: İdeal)")
            plt.show()
            return
            
        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        
        try:
            # 1. Anomali şiddeti dağılımı (mesafe sıçrama)
            if 'distance_diff' in self.proximity_alerts.columns:
                distance_jumps = self.proximity_alerts['distance_diff']
                axes[0,0].hist(distance_jumps, bins=30, color=self.colors['danger'], alpha=0.7, edgecolor='black')
                axes[0,0].set_title('🚨 Mesafe Sıçrama Dağılımı', fontsize=14, fontweight='bold')
                axes[0,0].set_xlabel('Mesafe Sıçrama (m)')
                axes[0,0].set_ylabel('Anomaly Sayısı')
                axes[0,0].grid(True, alpha=0.3)
                axes[0,0].axvline(distance_jumps.mean(), color=self.colors['warning'], linestyle='--',
                                 label=f'Ortalama: {distance_jumps.mean():.1f}m')
                axes[0,0].legend()
            
            # 2. MAC adresi başına anomaly sayısı
            mac_anomaly_counts = self.proximity_alerts['smac'].value_counts().head(10)
            axes[0,1].barh(range(len(mac_anomaly_counts)), mac_anomaly_counts.values, 
                          color=self.colors['warning'])
            axes[0,1].set_yticks(range(len(mac_anomaly_counts)))
            axes[0,1].set_yticklabels([mac[:15] + '...' if len(mac) > 15 else mac 
                                      for mac in mac_anomaly_counts.index])
            axes[0,1].set_title(' En Çok Anomaly Üreten MAC\'ler', fontweight='bold')
            axes[0,1].set_xlabel('Anomaly Sayısı')
            
            # 3. Zaman içinde anomaly dağılımı
            if 'timestamp_1' in self.proximity_alerts.columns:
                hourly_anomalies = self.proximity_alerts.set_index('timestamp_1').resample('1H').size()
                axes[1,0].plot(hourly_anomalies.index, hourly_anomalies.values, 
                              color=self.colors['danger'], linewidth=2, marker='s', markersize=4)
                axes[1,0].set_title(' Saatlik Proximity Anomaly Sayısı', fontweight='bold')
                axes[1,0].set_xlabel('Zaman')
                axes[1,0].set_ylabel('Anomaly Sayısı')
                axes[1,0].tick_params(axis='x', rotation=45)
                axes[1,0].grid(True, alpha=0.3)
            
            # 4. Zaman penceresi vs anomaly ilişkisi
            if 'time_window_sec' in self.proximity_alerts.columns:
                time_windows = self.proximity_alerts['time_window_sec']
                axes[1,1].scatter(time_windows, self.proximity_alerts['distance_diff'], 
                                 alpha=0.6, color=self.colors['purple'], s=30)
                axes[1,1].set_title('⏰ Zaman Penceresi vs Mesafe Sıçrama', fontweight='bold')
                axes[1,1].set_xlabel('Zaman Penceresi (saniye)')
                axes[1,1].set_ylabel('Mesafe Sıçrama (m)')
                axes[1,1].grid(True, alpha=0.3)
            
            plt.tight_layout()
            plt.savefig(f'{self.png_path}proximity_anomaly_dashboard.png', dpi=300, bbox_inches='tight')
            print("✅ Proximity anomaly dashboard kaydedildi")
            plt.show()
            
        except Exception as e:
            print(f"❌ Proximity anomaly dashboard oluşturulamadı: {e}")
    
    def create_temporal_analysis(self):
        """Zamansal analiz grafikleri"""
        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        
        try:
            # 1. Günlük mesafe varyasyonu
            if self.raw_distance_data is not None and len(self.raw_distance_data) > 0:
                daily_stats = self.raw_distance_data.groupby(self.raw_distance_data['timestamp'].dt.date)['distance'].agg(['mean', 'std', 'min', 'max']).reset_index()
                
                axes[0,0].fill_between(range(len(daily_stats)), 
                                      daily_stats['mean'] - daily_stats['std'],
                                      daily_stats['mean'] + daily_stats['std'],
                                      alpha=0.3, color=self.colors['info'])
                axes[0,0].plot(range(len(daily_stats)), daily_stats['mean'], 
                              color=self.colors['primary'], linewidth=2, marker='o')
                axes[0,0].set_title('📅 Günlük Mesafe İstatistikleri', fontweight='bold')
                axes[0,0].set_xlabel('Gün')
                axes[0,0].set_ylabel('Mesafe (m)')
                axes[0,0].grid(True, alpha=0.3)
            
            # 2. Anomaly şiddeti vs frekans analizi
            if self.proximity_alerts is not None and len(self.proximity_alerts) > 0 and 'distance_diff' in self.proximity_alerts.columns:
                # Mesafe sıçrama aralıklarına göre gruplama
                bins = [0, 10, 20, 50, 100, float('inf')]
                labels = ['0-10m', '10-20m', '20-50m', '50-100m', '100m+']
                self.proximity_alerts['severity_group'] = pd.cut(self.proximity_alerts['distance_diff'], 
                                                               bins=bins, labels=labels, include_lowest=True)
                severity_counts = self.proximity_alerts['severity_group'].value_counts()
                
                axes[0,1].pie(severity_counts.values, labels=severity_counts.index, autopct='%1.1f%%',
                             colors=[self.colors['success'], self.colors['info'], self.colors['warning'], 
                                    self.colors['danger'], self.colors['purple']])
                axes[0,1].set_title('🎯 Anomaly Şiddeti Dağılımı', fontweight='bold')
            else:
                # Anomaly yoksa güvenlik mesajı
                axes[0,1].text(0.5, 0.5, '🛡️ Güvenli!\n\nHiç proximity anomaly\ntespit edilmedi\n\nMesafe değişimleri normal', 
                              horizontalalignment='center', verticalalignment='center',
                              transform=axes[0,1].transAxes, fontsize=14, fontweight='bold',
                              bbox=dict(boxstyle="round,pad=0.3", facecolor=self.colors['success'], alpha=0.7))
                axes[0,1].set_title('🎯 Anomaly Şiddeti Dağılımı', fontweight='bold')
                axes[0,1].axis('off')
            
            # 3. MAC aktivite haritası
            if self.raw_distance_data is not None and len(self.raw_distance_data) > 0:
                # En aktif 10 MAC'i al
                top_macs = self.raw_distance_data['smac'].value_counts().head(10)
                mac_hourly_activity = []
                
                for mac in top_macs.index:
                    mac_data = self.raw_distance_data[self.raw_distance_data['smac'] == mac]
                    hourly_counts = mac_data.groupby(mac_data['timestamp'].dt.hour).size()
                    mac_hourly_activity.append(hourly_counts.reindex(range(24), fill_value=0))
                
                activity_matrix = np.array(mac_hourly_activity)
                im = axes[1,0].imshow(activity_matrix, cmap='YlOrRd', aspect='auto')
                axes[1,0].set_title('🗺️ MAC Aktivite Haritası (Saatlik)', fontweight='bold')
                axes[1,0].set_xlabel('Saat')
                axes[1,0].set_ylabel('MAC Adresi')
                axes[1,0].set_yticks(range(len(top_macs.index)))
                axes[1,0].set_yticklabels([mac[:10] + '...' for mac in top_macs.index])
                plt.colorbar(im, ax=axes[1,0], label='Aktivite Sayısı')
            
            # 4. Mesafe dağılımı karşılaştırması
            if (self.raw_distance_data is not None and self.proximity_alerts is not None and 
                len(self.raw_distance_data) > 0 and len(self.proximity_alerts) > 0):
                
                # Normal mesafeler vs anomaly mesafeleri
                normal_distances = self.raw_distance_data['distance']
                if 'distance_1' in self.proximity_alerts.columns and 'distance_2' in self.proximity_alerts.columns:
                    anomaly_distances = pd.concat([self.proximity_alerts['distance_1'], 
                                                  self.proximity_alerts['distance_2']])
                    
                    axes[1,1].hist(normal_distances, bins=30, alpha=0.7, label='Normal Mesafeler', 
                                  color=self.colors['success'], density=True)
                    axes[1,1].hist(anomaly_distances, bins=30, alpha=0.7, label='Anomaly Mesafeleri', 
                                  color=self.colors['danger'], density=True)
                    axes[1,1].set_title('📊 Normal vs Anomaly Mesafe Dağılımı', fontweight='bold')
                    axes[1,1].set_xlabel('Mesafe (m)')
                    axes[1,1].set_ylabel('Yoğunluk')
                    axes[1,1].legend()
                    axes[1,1].grid(True, alpha=0.3)
            else:
                # Anomaly yoksa sadece normal mesafeler
                if self.raw_distance_data is not None and len(self.raw_distance_data) > 0:
                    normal_distances = self.raw_distance_data['distance']
                    axes[1,1].hist(normal_distances, bins=30, alpha=0.7, label='Tüm Mesafeler Normal', 
                                  color=self.colors['success'], density=True)
                    axes[1,1].set_title('📊 Normal vs Anomaly Mesafe Dağılımı', fontweight='bold')
                    axes[1,1].set_xlabel('Mesafe (m)')
                    axes[1,1].set_ylabel('Yoğunluk')
                    axes[1,1].legend()
                    axes[1,1].grid(True, alpha=0.3)
                    
                    # Pozitif mesaj ekle
                    axes[1,1].text(0.7, 0.8, '✅ Sadece Normal\nMesafeler Mevcut', 
                                  transform=axes[1,1].transAxes, fontsize=12, fontweight='bold',
                                  bbox=dict(boxstyle="round,pad=0.3", facecolor=self.colors['success'], alpha=0.7))
                else:
                    # Hiç veri yoksa
                    axes[1,1].text(0.5, 0.5, '📊 Veri Bulunamadı\n\nMesafe verisi\nmevcut değil', 
                                  horizontalalignment='center', verticalalignment='center',
                                  transform=axes[1,1].transAxes, fontsize=14, fontweight='bold',
                                  bbox=dict(boxstyle="round,pad=0.3", facecolor=self.colors['warning'], alpha=0.7))
                    axes[1,1].set_title('📊 Normal vs Anomaly Mesafe Dağılımı', fontweight='bold')
                    axes[1,1].axis('off')
            
            plt.tight_layout()
            plt.savefig(f'{self.png_path}proximity_temporal_analysis.png', dpi=300, bbox_inches='tight')
            print("✅ Zamansal analiz grafiği kaydedildi")
            plt.show()
            
        except Exception as e:
            print(f"❌ Zamansal analiz grafiği oluşturulamadı: {e}")
    
    def create_summary_report(self):
        """Özet rapor dosyası oluştur"""
        try:
            summary = {
                '📍 PROXIMITY ALERT ANALİZ ÖZETİ': {
                    'Toplam Mesafe Ölçümü': len(self.raw_distance_data) if self.raw_distance_data is not None else 'N/A',
                    'Unique MAC Adresi': self.raw_distance_data['smac'].nunique() if self.raw_distance_data is not None else 'N/A',
                    'Proximity Anomaly Sayısı': len(self.proximity_alerts) if self.proximity_alerts is not None else 'N/A',
                    'Ortalama Mesafe': f"{self.raw_distance_data['distance'].mean():.2f}m" if self.raw_distance_data is not None else 'N/A',
                    'Maksimum Mesafe': f"{self.raw_distance_data['distance'].max():.2f}m" if self.raw_distance_data is not None else 'N/A',
                    'Analiz Tarihi': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                },
                '🚨 ANOMALİ İSTATİSTİKLERİ': {},
                '📊 MESAFE İSTATİSTİKLERİ': {}
            }
            
            # Anomali istatistikleri
            if self.proximity_alerts is not None and len(self.proximity_alerts) > 0:
                if 'distance_diff' in self.proximity_alerts.columns:
                    summary['🚨 ANOMALİ İSTATİSTİKLERİ']['Ortalama Mesafe Sıçrama'] = f"{self.proximity_alerts['distance_diff'].mean():.2f}m"
                    summary['🚨 ANOMALİ İSTATİSTİKLERİ']['Maksimum Mesafe Sıçrama'] = f"{self.proximity_alerts['distance_diff'].max():.2f}m"
                    summary['🚨 ANOMALİ İSTATİSTİKLERİ']['Anomalili MAC Sayısı'] = self.proximity_alerts['smac'].nunique()
                
                if 'time_window_sec' in self.proximity_alerts.columns:
                    summary['🚨 ANOMALİ İSTATİSTİKLERİ']['Ortalama Zaman Penceresi'] = f"{self.proximity_alerts['time_window_sec'].mean():.1f}s"
            
            # Mesafe istatistikleri
            if self.raw_distance_data is not None and len(self.raw_distance_data) > 0:
                summary['📊 MESAFE İSTATİSTİKLERİ']['Mesafe Aralığı'] = f"{self.raw_distance_data['distance'].min():.1f}m - {self.raw_distance_data['distance'].max():.1f}m"
                summary['📊 MESAFE İSTATİSTİKLERİ']['Standart Sapma'] = f"{self.raw_distance_data['distance'].std():.2f}m"
                summary['📊 MESAFE İSTATİSTİKLERİ']['En Aktif MAC'] = str(self.raw_distance_data['smac'].value_counts().index[0])[:20] + '...'
            
            # Raporu dosyaya kaydet
            with open(f'{self.docs_path}proximity_alert_summary.txt', 'w', encoding='utf-8') as f:
                f.write("=" * 60 + "\n")
                f.write("PROXIMITY ALERT ANALİZ RAPORU\n")
                f.write("=" * 60 + "\n\n")
                
                for category, items in summary.items():
                    f.write(f"{category}\n")
                    f.write("-" * 40 + "\n")
                    for key, value in items.items():
                        f.write(f"{key}: {value}\n")
                    f.write("\n")
            
            print("📋 Proximity Alert özet raporu kaydedildi!")
            
        except Exception as e:
            print(f"❌ Özet rapor oluşturulamadı: {e}")
    
    def generate_all_visualizations(self):
        """Tüm görselleştirmeleri oluştur"""
        print("🎨 Proximity Alert Analizi Görselleştirme Başlatılıyor...\n")
        
        # Verileri yükle
        self.load_data()
        
        if self.raw_distance_data is None or len(self.raw_distance_data) == 0:
            print("❌ Mesafe verisi bulunamadı! Görselleştirme durduruldu.")
            return
        
        # Grafikleri oluştur
        print("\n📏 Mesafe analizi grafikleri oluşturuluyor...")
        self.create_distance_analysis()
        
        print("\n🚨 Proximity anomaly dashboard oluşturuluyor...")
        self.create_anomaly_dashboard()
        
        print("\n⏰ Zamansal analiz grafikleri oluşturuluyor...")
        self.create_temporal_analysis()
        
        print("\n📋 Özet rapor oluşturuluyor...")
        self.create_summary_report()
        
        print("\n🎉 Proximity Alert görselleştirmeleri tamamlandı!")
        print(f"📁 Dosyalar kaydedildi: {self.docs_path}")
        print("\n📋 Oluşturulan dosyalar:")
        print("   • proximity_distance_analysis.png - Mesafe analizi")
        print("   • proximity_anomaly_dashboard.png - Anomaly dashboard")
        print("   • proximity_temporal_analysis.png - Zamansal analiz")
        print("   • proximity_alert_summary.txt - Özet rapor")

if __name__ == "__main__":
    # Görselleştirici oluştur ve çalıştır
    visualizer = ProximityAlertVisualizer()
    visualizer.generate_all_visualizations() 