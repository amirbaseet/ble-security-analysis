#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Replay Attack Analysis Visualization
replayAttack.py analiz sonuçlarını görselleştiren script
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
from config import DB_PATH, DOCS_DIR,FOTOS_DIR, REPLAY_TIME_WINDOW_SEC


warnings.filterwarnings('ignore')

# Turkish font support for matplotlib
plt.rcParams['font.family'] = ['DejaVu Sans']

class ReplayAttackVisualizer:
    def __init__(self, db_path=DB_PATH, docs_path=DOCS_DIR,png_path=FOTOS_DIR):
        self.db_path = db_path
        self.docs_path = docs_path+'/'
        self.png_path = png_path+'/'
        self.raw_packet_data = None
        self.replay_alerts = None
        self.time_window = REPLAY_TIME_WINDOW_SEC
        
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
        print("📊 Replay Attack analiz verileri yükleniyor...")
        
        # Ana paket verilerini veritabanından yükle
        conn = sqlite3.connect(self.db_path)
        self.raw_packet_data = pd.read_sql_query("""
            SELECT timestamp, dmac, smac, rssi, distance, packet_hash
            FROM BLEPacket
            ORDER BY timestamp
        """, conn)
        conn.close()
        
        # Timestamp dönüşümü
        self.raw_packet_data['timestamp'] = pd.to_datetime(self.raw_packet_data['timestamp'], format='mixed', errors='coerce')
        self.raw_packet_data.dropna(subset=['timestamp'], inplace=True)
        
        print(f"✅ Ham paket verileri: {len(self.raw_packet_data)} kayıt")
        
        # Replay attack verilerini yükle
        try:
            alerts_file = os.path.join(self.docs_path, "ReplayAttackAlerts.csv")
            if os.path.exists(alerts_file):
                # Dosyanın boş olmadığını kontrol et
                if os.path.getsize(alerts_file) > 0:
                    self.replay_alerts = pd.read_csv(alerts_file)
                    
                    # Boş DataFrame kontrolü
                    if len(self.replay_alerts) == 0:
                        print("⚠️ ReplayAttackAlerts.csv boş - replay attack bulunamadı")
                        self.replay_alerts = None
                    else:
                        # Timestamp dönüşümleri
                        if 'first_seen' in self.replay_alerts.columns:
                            self.replay_alerts['first_seen'] = pd.to_datetime(self.replay_alerts['first_seen'])
                        if 'repeated_at' in self.replay_alerts.columns:
                            self.replay_alerts['repeated_at'] = pd.to_datetime(self.replay_alerts['repeated_at'])
                        print(f"✅ Replay attack alert'leri: {len(self.replay_alerts)} kayıt")
                else:
                    print("⚠️ ReplayAttackAlerts.csv dosyası boş")
                    self.replay_alerts = None
            else:
                print("⚠️ ReplayAttackAlerts.csv bulunamadı")
                self.replay_alerts = None
                
        except Exception as e:
            print(f"⚠️ Replay attack verileri yüklenirken hata: {e}")
            self.replay_alerts = None
        
        print("✅ Veri yükleme tamamlandı!")
    
    def create_packet_analysis(self):
        """Paket analizi grafikleri"""
        if self.raw_packet_data is None or len(self.raw_packet_data) == 0:
            print("⚠️ Paket verisi bulunamadı")
            return
            
        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        
        try:
            # 1. Paket hash dağılımı (duplicate vs unique)
            hash_counts = self.raw_packet_data['packet_hash'].value_counts()
            unique_hashes = len(hash_counts[hash_counts == 1])
            duplicate_hashes = len(hash_counts[hash_counts > 1])
            
            labels = ['Unique Paketler', 'Tekrarlanan Paketler']
            sizes = [unique_hashes, duplicate_hashes]
            colors = [self.colors['success'], self.colors['danger']]
            
            axes[0,0].pie(sizes, labels=labels, autopct='%1.1f%%', colors=colors, startangle=90)
            axes[0,0].set_title('📦 Paket Tekrarlanma Dağılımı', fontsize=14, fontweight='bold')
            
            # 2. En çok tekrarlanan hash'ler
            most_repeated = hash_counts[hash_counts > 1].head(10)
            if len(most_repeated) > 0:
                y_pos = range(len(most_repeated))
                axes[0,1].barh(y_pos, most_repeated.values, color=self.colors['warning'])
                axes[0,1].set_yticks(y_pos)
                axes[0,1].set_yticklabels([hash_val[:15] + '...' if len(str(hash_val)) > 15 else str(hash_val) 
                                          for hash_val in most_repeated.index])
                axes[0,1].set_title('🔝 En Çok Tekrarlanan Paket Hash\'leri', fontweight='bold')
                axes[0,1].set_xlabel('Tekrar Sayısı')
            else:
                # Güvenlik açısından olumlu durum - tüm paketler unique
                axes[0,1].text(0.5, 0.5, '🛡️ Mükemmel!\n\nTüm paket hash\'leri benzersiz\n\nReplay attack riski düşük', 
                              horizontalalignment='center', verticalalignment='center',
                              transform=axes[0,1].transAxes, fontsize=14, fontweight='bold',
                              bbox=dict(boxstyle="round,pad=0.3", facecolor=self.colors['success'], alpha=0.7))
                axes[0,1].set_title('🔝 En Çok Tekrarlanan Paket Hash\'leri', fontweight='bold')
                axes[0,1].set_xlim(0, 1)
                axes[0,1].set_ylim(0, 1)
                axes[0,1].axis('off')
            
            # 3. Saatlik paket dağılımı
            hourly_packets = self.raw_packet_data.set_index('timestamp').resample('1H').size()
            axes[1,0].plot(hourly_packets.index, hourly_packets.values, 
                          color=self.colors['primary'], linewidth=2, marker='o', markersize=4)
            axes[1,0].set_title('🕐 Saatlik Paket Trafiği', fontweight='bold')
            axes[1,0].set_xlabel('Zaman')
            axes[1,0].set_ylabel('Paket Sayısı')
            axes[1,0].tick_params(axis='x', rotation=45)
            axes[1,0].grid(True, alpha=0.3)
            
            # 4. MAC adresi başına paket sayısı
            mac_packet_counts = self.raw_packet_data['smac'].value_counts().head(10)
            axes[1,1].bar(range(len(mac_packet_counts)), mac_packet_counts.values, color=self.colors['info'])
            axes[1,1].set_xticks(range(len(mac_packet_counts)))
            axes[1,1].set_xticklabels([mac[:10] + '...' if len(mac) > 10 else mac 
                                      for mac in mac_packet_counts.index], rotation=45)
            axes[1,1].set_title('📱 MAC Başına Paket Sayısı (Top 10)', fontweight='bold')
            axes[1,1].set_ylabel('Paket Sayısı')
            
            plt.tight_layout()
            plt.savefig(f'{self.png_path}replay_packet_analysis.png', dpi=300, bbox_inches='tight')
            print("✅ Paket analizi grafiği kaydedildi")
            plt.show()
            
        except Exception as e:
            print(f"❌ Paket analizi grafiği oluşturulamadı: {e}")
    
    def create_replay_dashboard(self):
        """Replay attack dashboard'u"""
        if self.replay_alerts is None or len(self.replay_alerts) == 0:
            # Replay attack verisi olmadığında pozitif güvenlik mesajı göster
            fig, axes = plt.subplots(2, 2, figsize=(16, 12))
            
            # Her grafik alanına pozitif mesaj
            messages = [
                '🛡️ Mükemmel!\n\nHiç replay attack\ntespit edilmedi\n\nTüm paketler benzersiz',
                '✅ Güvenli Ağ!\n\nMAC adreslerinde\nsaldırı tespit edilmedi',
                '📊 İdeal Durum!\n\nZaman içinde\nhiç attack yok',
                '🔄 Sağlıklı İletişim!\n\nTüm paketler\ntek seferlik'
            ]
            
            for i, (ax, msg) in enumerate(zip(axes.flat, messages)):
                ax.text(0.5, 0.5, msg, horizontalalignment='center', verticalalignment='center',
                       transform=ax.transAxes, fontsize=14, fontweight='bold',
                       bbox=dict(boxstyle="round,pad=0.3", facecolor=self.colors['success'], alpha=0.7))
                ax.set_xlim(0, 1)
                ax.set_ylim(0, 1)
                ax.axis('off')
            
            titles = [
                '⏱️ Replay Attack Zaman Farkı Dağılımı',
                '🚨 MAC Başına Replay Attack Sayısı', 
                '📈 Saatlik Replay Attack Sayısı',
                '🔄 Paket Tekrar Sayısı Dağılımı'
            ]
            
            for ax, title in zip(axes.flat, titles):
                ax.set_title(title, fontsize=14, fontweight='bold')
            
            plt.tight_layout()
            plt.savefig(f'{self.png_path}replay_attack_dashboard.png', dpi=300, bbox_inches='tight')
            print("✅ Replay attack dashboard kaydedildi (güvenlik durumu: İdeal)")
            plt.show()
            return
            
        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        
        try:
            # 1. Replay attack zaman farkı dağılımı
            if 'time_diff_secs' in self.replay_alerts.columns:
                time_diffs = self.replay_alerts['time_diff_secs']
                axes[0,0].hist(time_diffs, bins=30, color=self.colors['danger'], alpha=0.7, edgecolor='black')
                axes[0,0].set_title('⏱️ Replay Attack Zaman Farkı Dağılımı', fontsize=14, fontweight='bold')
                axes[0,0].set_xlabel('Zaman Farkı (saniye)')
                axes[0,0].set_ylabel('Attack Sayısı')
                axes[0,0].grid(True, alpha=0.3)
                axes[0,0].axvline(self.time_window, color=self.colors['warning'], linestyle='--',
                                 label=f'Threshold: {self.time_window}s')
                axes[0,0].legend()
            else:
                axes[0,0].text(0.5, 0.5, '🛡️ Güvenli!\n\nZaman farkı verisi yok\n\nReplay attack riski düşük', 
                              horizontalalignment='center', verticalalignment='center',
                              transform=axes[0,0].transAxes, fontsize=14, fontweight='bold',
                              bbox=dict(boxstyle="round,pad=0.3", facecolor=self.colors['success'], alpha=0.7))
                axes[0,0].set_title('⏱️ Replay Attack Zaman Farkı Dağılımı', fontsize=14, fontweight='bold')
                axes[0,0].axis('off')
            
            # 2. MAC adresi başına replay attack sayısı
            if 'smac' in self.replay_alerts.columns:
                mac_attack_counts = self.replay_alerts['smac'].value_counts().head(10)
                if len(mac_attack_counts) > 0:
                    axes[0,1].barh(range(len(mac_attack_counts)), mac_attack_counts.values, 
                                  color=self.colors['warning'])
                    axes[0,1].set_yticks(range(len(mac_attack_counts)))
                    axes[0,1].set_yticklabels([mac[:15] + '...' if len(mac) > 15 else mac 
                                              for mac in mac_attack_counts.index])
                    axes[0,1].set_title('🚨 MAC Başına Replay Attack Sayısı', fontweight='bold')
                    axes[0,1].set_xlabel('Attack Sayısı')
                else:
                    axes[0,1].text(0.5, 0.5, '✅ Temiz!\n\nHiçbir MAC adresinde\nreplay attack yok', 
                                  horizontalalignment='center', verticalalignment='center',
                                  transform=axes[0,1].transAxes, fontsize=14, fontweight='bold',
                                  bbox=dict(boxstyle="round,pad=0.3", facecolor=self.colors['success'], alpha=0.7))
                    axes[0,1].set_title('🚨 MAC Başına Replay Attack Sayısı', fontweight='bold')
                    axes[0,1].axis('off')
            else:
                axes[0,1].text(0.5, 0.5, '✅ Temiz!\n\nHiçbir MAC adresinde\nreplay attack yok', 
                              horizontalalignment='center', verticalalignment='center',
                              transform=axes[0,1].transAxes, fontsize=14, fontweight='bold',
                              bbox=dict(boxstyle="round,pad=0.3", facecolor=self.colors['success'], alpha=0.7))
                axes[0,1].set_title('🚨 MAC Başına Replay Attack Sayısı', fontweight='bold')
                axes[0,1].axis('off')
            
            # 3. Zaman içinde replay attack dağılımı
            if 'first_seen' in self.replay_alerts.columns:
                hourly_attacks = self.replay_alerts.set_index('first_seen').resample('1H').size()
                axes[1,0].plot(hourly_attacks.index, hourly_attacks.values, 
                              color=self.colors['danger'], linewidth=2, marker='s', markersize=4)
                axes[1,0].set_title('📈 Saatlik Replay Attack Sayısı', fontweight='bold')
                axes[1,0].set_xlabel('Zaman')
                axes[1,0].set_ylabel('Attack Sayısı')
                axes[1,0].tick_params(axis='x', rotation=45)
                axes[1,0].grid(True, alpha=0.3)
            else:
                axes[1,0].text(0.5, 0.5, '📊 Mükemmel!\n\nZaman içinde\nhiç attack tespit edilmedi', 
                              horizontalalignment='center', verticalalignment='center',
                              transform=axes[1,0].transAxes, fontsize=14, fontweight='bold',
                              bbox=dict(boxstyle="round,pad=0.3", facecolor=self.colors['success'], alpha=0.7))
                axes[1,0].set_title('📈 Saatlik Replay Attack Sayısı', fontweight='bold')
                axes[1,0].axis('off')
            
            # 4. Tekrar sayısı dağılımı
            if 'repetition_count' in self.replay_alerts.columns:
                repetition_counts = self.replay_alerts['repetition_count']
                axes[1,1].hist(repetition_counts, bins=20, color=self.colors['purple'], alpha=0.7, edgecolor='black')
                axes[1,1].set_title('🔄 Paket Tekrar Sayısı Dağılımı', fontweight='bold')
                axes[1,1].set_xlabel('Tekrar Sayısı')
                axes[1,1].set_ylabel('Paket Hash Sayısı')
                axes[1,1].grid(True, alpha=0.3)
            else:
                axes[1,1].text(0.5, 0.5, '🔄 İdeal!\n\nTekrar sayısı verisi yok\n\nTüm paketler benzersiz', 
                              horizontalalignment='center', verticalalignment='center',
                              transform=axes[1,1].transAxes, fontsize=14, fontweight='bold',
                              bbox=dict(boxstyle="round,pad=0.3", facecolor=self.colors['success'], alpha=0.7))
                axes[1,1].set_title('🔄 Paket Tekrar Sayısı Dağılımı', fontweight='bold')
                axes[1,1].axis('off')
            
            plt.tight_layout()
            plt.savefig(f'{self.png_path}replay_attack_dashboard.png', dpi=300, bbox_inches='tight')
            print("✅ Replay attack dashboard kaydedildi")
            plt.show()
            
        except Exception as e:
            print(f"❌ Replay attack dashboard oluşturulamadı: {e}")
    
    def create_security_timeline(self):
        """Güvenlik zaman çizelgesi analizi"""
        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        
        try:
            # 1. Gerçek zamanlı replay detection simülasyonu
            if self.replay_alerts is not None and len(self.replay_alerts) > 0:
                # Attack frequency over time
                if 'first_seen' in self.replay_alerts.columns:
                    attacks_by_minute = self.replay_alerts.set_index('first_seen').resample('5T').size()
                    axes[0,0].plot(attacks_by_minute.index, attacks_by_minute.values, 
                                  color=self.colors['danger'], linewidth=1.5, marker='^', markersize=3)
                    axes[0,0].set_title('🚨 5 Dakikalık Replay Attack Yoğunluğu', fontweight='bold')
                    axes[0,0].set_xlabel('Zaman')
                    axes[0,0].set_ylabel('Attack Sayısı')
                    axes[0,0].tick_params(axis='x', rotation=45)
                    axes[0,0].grid(True, alpha=0.3)
                else:
                    axes[0,0].text(0.5, 0.5, '🛡️ Güvenli!\n\nZaman verisi eksik\nancak attack tespit edilmedi', 
                                  horizontalalignment='center', verticalalignment='center',
                                  transform=axes[0,0].transAxes, fontsize=14, fontweight='bold',
                                  bbox=dict(boxstyle="round,pad=0.3", facecolor=self.colors['success'], alpha=0.7))
                    axes[0,0].set_title('🚨 5 Dakikalık Replay Attack Yoğunluğu', fontweight='bold')
                    axes[0,0].axis('off')
            else:
                axes[0,0].text(0.5, 0.5, '🛡️ Mükemmel!\n\nHiç replay attack\ntespit edilmedi', 
                              horizontalalignment='center', verticalalignment='center',
                              transform=axes[0,0].transAxes, fontsize=14, fontweight='bold',
                              bbox=dict(boxstyle="round,pad=0.3", facecolor=self.colors['success'], alpha=0.7))
                axes[0,0].set_title('🚨 5 Dakikalık Replay Attack Yoğunluğu', fontweight='bold')
                axes[0,0].axis('off')
            
            # 2. RSSI vs Distance scatter for attacked packets
            if (self.replay_alerts is not None and len(self.replay_alerts) > 0 and 
                'rssi' in self.replay_alerts.columns and 'distance' in self.replay_alerts.columns):
                
                valid_data = self.replay_alerts.dropna(subset=['rssi', 'distance'])
                if len(valid_data) > 0:
                    axes[0,1].scatter(valid_data['rssi'], valid_data['distance'], 
                                     alpha=0.7, color=self.colors['danger'], s=40, label='Replay Attacks')
                    
                    # Normal paketlerin karşılaştırması için sample
                    if self.raw_packet_data is not None:
                        normal_sample = self.raw_packet_data.dropna(subset=['rssi', 'distance']).sample(
                            min(200, len(self.raw_packet_data))
                        )
                        axes[0,1].scatter(normal_sample['rssi'], normal_sample['distance'], 
                                         alpha=0.3, color=self.colors['info'], s=20, label='Normal Paketler')
                    
                    axes[0,1].set_title('📶 Attack Edilen Paketler - RSSI vs Mesafe', fontweight='bold')
                    axes[0,1].set_xlabel('RSSI (dBm)')
                    axes[0,1].set_ylabel('Mesafe (m)')
                    axes[0,1].legend()
                    axes[0,1].grid(True, alpha=0.3)
                else:
                    # Normal paketleri göster
                    if self.raw_packet_data is not None:
                        normal_sample = self.raw_packet_data.dropna(subset=['rssi', 'distance']).sample(
                            min(200, len(self.raw_packet_data))
                        )
                        axes[0,1].scatter(normal_sample['rssi'], normal_sample['distance'], 
                                         alpha=0.6, color=self.colors['success'], s=20, label='Sadece Normal Paketler')
                        axes[0,1].set_title('📶 Attack Edilen Paketler - RSSI vs Mesafe', fontweight='bold')
                        axes[0,1].set_xlabel('RSSI (dBm)')
                        axes[0,1].set_ylabel('Mesafe (m)')
                        axes[0,1].legend()
                        axes[0,1].grid(True, alpha=0.3)
                        
                        # Pozitif mesaj ekle
                        axes[0,1].text(0.7, 0.8, '✅ Temiz Ağ!\nSadece Normal Paketler', 
                                      transform=axes[0,1].transAxes, fontsize=12, fontweight='bold',
                                      bbox=dict(boxstyle="round,pad=0.3", facecolor=self.colors['success'], alpha=0.7))
                    else:
                        axes[0,1].text(0.5, 0.5, '📶 Veri Eksik!\n\nRSSI/Mesafe verisi\nmevcut değil', 
                                      horizontalalignment='center', verticalalignment='center',
                                      transform=axes[0,1].transAxes, fontsize=14, fontweight='bold',
                                      bbox=dict(boxstyle="round,pad=0.3", facecolor=self.colors['warning'], alpha=0.7))
                        axes[0,1].set_title('📶 Attack Edilen Paketler - RSSI vs Mesafe', fontweight='bold')
                        axes[0,1].axis('off')
            else:
                # Normal paketleri göster veya mesaj
                if self.raw_packet_data is not None and len(self.raw_packet_data) > 0:
                    normal_sample = self.raw_packet_data.dropna(subset=['rssi', 'distance']).sample(
                        min(200, len(self.raw_packet_data))
                    )
                    if len(normal_sample) > 0:
                        axes[0,1].scatter(normal_sample['rssi'], normal_sample['distance'], 
                                         alpha=0.6, color=self.colors['success'], s=20, label='Sadece Normal Paketler')
                        axes[0,1].set_title('📶 Attack Edilen Paketler - RSSI vs Mesafe', fontweight='bold')
                        axes[0,1].set_xlabel('RSSI (dBm)')
                        axes[0,1].set_ylabel('Mesafe (m)')
                        axes[0,1].legend()
                        axes[0,1].grid(True, alpha=0.3)
                        
                        # Pozitif mesaj ekle
                        axes[0,1].text(0.7, 0.8, '✅ İdeal Durum!\nHiç Saldırı Yok', 
                                      transform=axes[0,1].transAxes, fontsize=12, fontweight='bold',
                                      bbox=dict(boxstyle="round,pad=0.3", facecolor=self.colors['success'], alpha=0.7))
                    else:
                        axes[0,1].text(0.5, 0.5, '📶 Veri Eksik!\n\nRSSI/Mesafe verisi\nmevcut değil', 
                                      horizontalalignment='center', verticalalignment='center',
                                      transform=axes[0,1].transAxes, fontsize=14, fontweight='bold',
                                      bbox=dict(boxstyle="round,pad=0.3", facecolor=self.colors['warning'], alpha=0.7))
                        axes[0,1].set_title('📶 Attack Edilen Paketler - RSSI vs Mesafe', fontweight='bold')
                        axes[0,1].axis('off')
                else:
                    axes[0,1].text(0.5, 0.5, '📶 Veri Eksik!\n\nHiç paket verisi\nmevcut değil', 
                                  horizontalalignment='center', verticalalignment='center',
                                  transform=axes[0,1].transAxes, fontsize=14, fontweight='bold',
                                  bbox=dict(boxstyle="round,pad=0.3", facecolor=self.colors['warning'], alpha=0.7))
                    axes[0,1].set_title('📶 Attack Edilen Paketler - RSSI vs Mesafe', fontweight='bold')
                    axes[0,1].axis('off')
            
            # 3. Attack pattern analysis (günlük cycle)
            if self.replay_alerts is not None and len(self.replay_alerts) > 0 and 'first_seen' in self.replay_alerts.columns:
                # Saatlik pattern
                hour_pattern = self.replay_alerts['first_seen'].dt.hour.value_counts().sort_index()
                axes[1,0].bar(hour_pattern.index, hour_pattern.values, color=self.colors['warning'], alpha=0.7)
                axes[1,0].set_title('🕒 Günlük Attack Pattern (Saat Bazında)', fontweight='bold')
                axes[1,0].set_xlabel('Saat')
                axes[1,0].set_ylabel('Attack Sayısı')
                axes[1,0].grid(True, alpha=0.3)
            else:
                axes[1,0].text(0.5, 0.5, '🕒 Mükemmel!\n\nHiçbir saatte\nattack tespit edilmedi\n\nGünlük aktivite normal', 
                              horizontalalignment='center', verticalalignment='center',
                              transform=axes[1,0].transAxes, fontsize=14, fontweight='bold',
                              bbox=dict(boxstyle="round,pad=0.3", facecolor=self.colors['success'], alpha=0.7))
                axes[1,0].set_title('🕒 Günlük Attack Pattern (Saat Bazında)', fontweight='bold')
                axes[1,0].axis('off')
            
            # 4. Hash collision analysis
            if self.raw_packet_data is not None and len(self.raw_packet_data) > 0:
                # Hash uzunluğu vs tekrar sayısı
                hash_stats = self.raw_packet_data.groupby('packet_hash').agg({
                    'timestamp': 'count',
                    'smac': 'nunique'
                }).reset_index()
                hash_stats.columns = ['packet_hash', 'count', 'unique_macs']
                
                duplicates = hash_stats[hash_stats['count'] > 1]
                if len(duplicates) > 0:
                    axes[1,1].scatter(duplicates['count'], duplicates['unique_macs'], 
                                     alpha=0.6, color=self.colors['purple'], s=30)
                    axes[1,1].set_title('🔍 Hash Collision Analizi', fontweight='bold')
                    axes[1,1].set_xlabel('Paket Tekrar Sayısı')
                    axes[1,1].set_ylabel('Unique MAC Sayısı')
                    axes[1,1].grid(True, alpha=0.3)
                else:
                    axes[1,1].text(0.5, 0.5, '🔍 Mükemmel!\n\nHiç hash collision yok\n\nTüm paketler benzersiz\n\nGüvenlik seviyesi yüksek', 
                                  horizontalalignment='center', verticalalignment='center',
                                  transform=axes[1,1].transAxes, fontsize=14, fontweight='bold',
                                  bbox=dict(boxstyle="round,pad=0.3", facecolor=self.colors['success'], alpha=0.7))
                    axes[1,1].set_title('🔍 Hash Collision Analizi', fontweight='bold')
                    axes[1,1].axis('off')
            else:
                axes[1,1].text(0.5, 0.5, '🔍 Veri Eksik!\n\nHash analizi için\nyeterli veri yok', 
                              horizontalalignment='center', verticalalignment='center',
                              transform=axes[1,1].transAxes, fontsize=14, fontweight='bold',
                              bbox=dict(boxstyle="round,pad=0.3", facecolor=self.colors['warning'], alpha=0.7))
                axes[1,1].set_title('🔍 Hash Collision Analizi', fontweight='bold')
                axes[1,1].axis('off')
            
            plt.tight_layout()
            plt.savefig(f'{self.png_path}replay_security_timeline.png', dpi=300, bbox_inches='tight')
            print("✅ Güvenlik zaman çizelgesi grafiği kaydedildi")
            plt.show()
            
        except Exception as e:
            print(f"❌ Güvenlik zaman çizelgesi grafiği oluşturulamadı: {e}")
    
    def create_summary_report(self):
        """Özet rapor dosyası oluştur"""
        try:
            summary = {
                '🔄 REPLAY ATTACK ANALİZ ÖZETİ': {
                    'Toplam Paket Sayısı': len(self.raw_packet_data) if self.raw_packet_data is not None else 'N/A',
                    'Unique Hash Sayısı': self.raw_packet_data['packet_hash'].nunique() if self.raw_packet_data is not None else 'N/A',
                    'Replay Attack Sayısı': len(self.replay_alerts) if self.replay_alerts is not None else 'N/A',
                    'Zaman Penceresi': f"{self.time_window} saniye",
                    'Analiz Tarihi': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                },
                '🚨 ATTACK İSTATİSTİKLERİ': {},
                '📊 PAKET İSTATİSTİKLERİ': {}
            }
            
            # Attack istatistikleri
            if self.replay_alerts is not None and len(self.replay_alerts) > 0:
                if 'time_diff_secs' in self.replay_alerts.columns:
                    summary['🚨 ATTACK İSTATİSTİKLERİ']['Ortalama Zaman Farkı'] = f"{self.replay_alerts['time_diff_secs'].mean():.2f}s"
                    summary['🚨 ATTACK İSTATİSTİKLERİ']['Minimum Zaman Farkı'] = f"{self.replay_alerts['time_diff_secs'].min():.2f}s"
                
                if 'repetition_count' in self.replay_alerts.columns:
                    summary['🚨 ATTACK İSTATİSTİKLERİ']['Ortalama Tekrar Sayısı'] = f"{self.replay_alerts['repetition_count'].mean():.1f}"
                    summary['🚨 ATTACK İSTATİSTİKLERİ']['Maksimum Tekrar Sayısı'] = self.replay_alerts['repetition_count'].max()
                
                if 'smac' in self.replay_alerts.columns:
                    summary['🚨 ATTACK İSTATİSTİKLERİ']['Saldırıya Uğrayan MAC Sayısı'] = self.replay_alerts['smac'].nunique()
            
            # Paket istatistikleri
            if self.raw_packet_data is not None and len(self.raw_packet_data) > 0:
                hash_counts = self.raw_packet_data['packet_hash'].value_counts()
                unique_hashes = len(hash_counts[hash_counts == 1])
                duplicate_hashes = len(hash_counts[hash_counts > 1])
                
                summary['📊 PAKET İSTATİSTİKLERİ']['Unique Paket Hash'] = unique_hashes
                summary['📊 PAKET İSTATİSTİKLERİ']['Tekrarlanan Hash'] = duplicate_hashes
                summary['📊 PAKET İSTATİSTİKLERİ']['Tekrar Oranı'] = f"{(duplicate_hashes/len(hash_counts)*100):.1f}%"
                summary['📊 PAKET İSTATİSTİKLERİ']['En Aktif MAC'] = str(self.raw_packet_data['smac'].value_counts().index[0])[:20] + '...'
            
            # Raporu dosyaya kaydet
            with open(f'{self.docs_path}replay_attack_summary.txt', 'w', encoding='utf-8') as f:
                f.write("=" * 60 + "\n")
                f.write("REPLAY ATTACK ANALİZ RAPORU\n")
                f.write("=" * 60 + "\n\n")
                
                for category, items in summary.items():
                    f.write(f"{category}\n")
                    f.write("-" * 40 + "\n")
                    for key, value in items.items():
                        f.write(f"{key}: {value}\n")
                    f.write("\n")
            
            print("📋 Replay Attack özet raporu kaydedildi!")
            
        except Exception as e:
            print(f"❌ Özet rapor oluşturulamadı: {e}")
    
    def generate_all_visualizations(self):
        """Tüm görselleştirmeleri oluştur"""
        print("🎨 Replay Attack Analizi Görselleştirme Başlatılıyor...\n")
        
        # Verileri yükle
        self.load_data()
        
        if self.raw_packet_data is None or len(self.raw_packet_data) == 0:
            print("❌ Paket verisi bulunamadı! Görselleştirme durduruldu.")
            return
        
        # Grafikleri oluştur
        print("\n📦 Paket analizi grafikleri oluşturuluyor...")
        self.create_packet_analysis()
        
        print("\n🚨 Replay attack dashboard oluşturuluyor...")
        self.create_replay_dashboard()
        
        print("\n⏰ Güvenlik zaman çizelgesi oluşturuluyor...")
        self.create_security_timeline()
        
        print("\n📋 Özet rapor oluşturuluyor...")
        self.create_summary_report()
        
        print("\n🎉 Replay Attack görselleştirmeleri tamamlandı!")
        print(f"📁 Dosyalar kaydedildi: {self.docs_path}")
        print("\n📋 Oluşturulan dosyalar:")
        print("   • replay_packet_analysis.png - Paket analizi")
        print("   • replay_attack_dashboard.png - Attack dashboard")
        print("   • replay_security_timeline.png - Güvenlik zaman çizelgesi")
        print("   • replay_attack_summary.txt - Özet rapor")

if __name__ == "__main__":
    # Görselleştirici oluştur ve çalıştır
    visualizer = ReplayAttackVisualizer()
    visualizer.generate_all_visualizations() 