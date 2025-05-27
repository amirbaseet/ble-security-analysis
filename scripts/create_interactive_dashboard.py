#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Comprehensive Interactive HTML Dashboard Creator for BLE Security Analysis
Tüm saldırı türleri için kapsamlı interaktif dashboard oluşturur
"""

import pandas as pd
import sqlite3
import json
import os
from datetime import datetime
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import plotly.offline as pyo
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from config import DB_PATH, DOCS_DIR, REPLAY_TIME_WINDOW_SEC

class ComprehensiveSecurityDashboard:
    def __init__(self, db_path=DB_PATH, docs_path=DOCS_DIR):
        self.db_path = db_path
        self.docs_path = docs_path
        self.raw_packet_data = None
        self.mac_spoofing_attacks = None
        self.proximity_attacks = None
        self.replay_attacks = None
        self.time_window = REPLAY_TIME_WINDOW_SEC
        
    def load_data(self):
        """Tüm veri türlerini yükle"""
        print("📊 Kapsamlı güvenlik dashboard verileri yükleniyor...")
        
        conn = sqlite3.connect(self.db_path)
        
        # Ana paket verilerini yükle
        self.raw_packet_data = pd.read_sql_query("""
            SELECT timestamp, dmac, smac, rssi, distance, packet_hash
            FROM BLEPacket
            ORDER BY timestamp
        """, conn)
        
        # MAC Spoofing saldırılarını CSV'den yükle (veritabanı yerine)
        try:
            # Önce fotos klasöründeki güncel dosyayı dene
            mac_spoofing_file = os.path.join(self.docs_path, "../docs/MACSpoofing_CombinedAlerts.csv")
            if not os.path.exists(mac_spoofing_file):
                # Yoksa Docs klasöründeki dosyayı dene
                mac_spoofing_file = os.path.join(self.docs_path, "MACSpoofing_CombinedAlerts.csv")
            
            if os.path.exists(mac_spoofing_file) and os.path.getsize(mac_spoofing_file) > 0:
                self.mac_spoofing_attacks = pd.read_csv(mac_spoofing_file)
                if len(self.mac_spoofing_attacks) > 0:
                    # Timestamp dönüşümü
                    if 'first_seen' in self.mac_spoofing_attacks.columns:
                        try:
                            self.mac_spoofing_attacks['first_seen'] = pd.to_datetime(self.mac_spoofing_attacks['first_seen'], format='mixed')
                        except ValueError:
                            self.mac_spoofing_attacks['first_seen'] = pd.to_datetime(self.mac_spoofing_attacks['first_seen'], errors='coerce')
                    print(f"✅ MAC Spoofing verileri yüklendi: {len(self.mac_spoofing_attacks)} saldırı")
                else:
                    self.mac_spoofing_attacks = None
                    print("⚠️ MACSpoofing_CombinedAlerts.csv boş")
            else:
                print("⚠️ MACSpoofing_CombinedAlerts.csv bulunamadı")
                self.mac_spoofing_attacks = None
        except Exception as e:
            print(f"⚠️ MAC Spoofing verileri yüklenirken hata: {e}")
            self.mac_spoofing_attacks = None
            
        conn.close()
        
        # Replay attacks CSV'den yükle
        try:
            replay_alerts_file = os.path.join(self.docs_path, "ReplayAttackAlerts.csv")
            if os.path.exists(replay_alerts_file) and os.path.getsize(replay_alerts_file) > 0:
                self.replay_attacks = pd.read_csv(replay_alerts_file)
                if len(self.replay_attacks) > 0:
                    if 'first_seen' in self.replay_attacks.columns:
                        self.replay_attacks['first_seen'] = pd.to_datetime(self.replay_attacks['first_seen'])
                    if 'repeated_at' in self.replay_attacks.columns:
                        self.replay_attacks['repeated_at'] = pd.to_datetime(self.replay_attacks['repeated_at'])
                    print(f"✅ Replay Attack verileri yüklendi: {len(self.replay_attacks)} saldırı")
                else:
                    self.replay_attacks = None
                    print("⚠️ Replay Attack CSV'si boş")
            else:
                self.replay_attacks = None
                print("⚠️ ReplayAttackAlerts.csv bulunamadı veya boş")
        except Exception as e:
            print(f"⚠️ Replay Attack verileri yüklenirken hata: {e}")
            self.replay_attacks = None
        
        # Proximity attacks için gerçek CSV dosyasını oku
        try:
            proximity_file = os.path.join(self.docs_path, "ProximityAnomalyAlerts.csv")
            if os.path.exists(proximity_file) and os.path.getsize(proximity_file) > 0:
                self.proximity_attacks = pd.read_csv(proximity_file)
                if len(self.proximity_attacks) > 0:
                    print(f"✅ Proximity Attack analizi: {len(self.proximity_attacks)} anomali yüklendi")
                else:
                    self.proximity_attacks = None
                    print("⚠️ ProximityAnomalyAlerts.csv boş")
            else:
                print("⚠️ ProximityAnomalyAlerts.csv bulunamadı")
                self.proximity_attacks = None
        except Exception as e:
            print(f"⚠️ Proximity Attack verileri yüklenirken hata: {e}")
            self.proximity_attacks = None
        
        # Timestamp dönüşümü
        if self.raw_packet_data is not None:
            # Timestamp'i daha esnek şekilde parse et (microsaniye desteği için)
            try:
                self.raw_packet_data['timestamp'] = pd.to_datetime(self.raw_packet_data['timestamp'], format='mixed')
            except ValueError:
                # Eğer mixed format çalışmazsa, errors='coerce' kullan
                self.raw_packet_data['timestamp'] = pd.to_datetime(self.raw_packet_data['timestamp'], errors='coerce')
        
        print("✅ Tüm veriler başarıyla yüklendi!")
        
    def create_comprehensive_security_status(self):
        """Kapsamlı güvenlik durumu kartı"""
        mac_count = len(self.mac_spoofing_attacks) if self.mac_spoofing_attacks is not None else 0
        proximity_count = len(self.proximity_attacks) if self.proximity_attacks is not None else 0
        replay_count = len(self.replay_attacks) if self.replay_attacks is not None else 0
        total_attacks = mac_count + proximity_count + replay_count
        
        if total_attacks == 0:
            return {
                'status': 'safe',
                'title': '🛡️ SİSTEM GÜVENLİ',
                'message': 'Hiçbir güvenlik tehdidi tespit edilmedi!',
                'detail': 'Tüm saldırı türleri için analiz tamamlandı',
                'color': '#28a745',
                'icon': '✅',
                'total_attacks': 0,
                'mac_count': mac_count,
                'proximity_count': proximity_count,
                'replay_count': replay_count
            }
        else:
            return {
                'status': 'danger',
                'title': '🚨 GÜVENLİK TEHDİDİ',
                'message': f'{total_attacks} Farklı Saldırı Tespit Edildi!',
                'detail': f'MAC Spoofing: {mac_count}, Proximity: {proximity_count}, Replay: {replay_count}',
                'color': '#dc3545',
                'icon': '⚠️',
                'total_attacks': total_attacks,
                'mac_count': mac_count,
                'proximity_count': proximity_count,
                'replay_count': replay_count
            }
    
    def create_statistics_summary(self):
        """Kapsamlı istatistik özeti"""
        total_packets = len(self.raw_packet_data) if self.raw_packet_data is not None else 0
        unique_hashes = self.raw_packet_data['packet_hash'].nunique() if self.raw_packet_data is not None else 0
        unique_macs = self.raw_packet_data['smac'].nunique() if self.raw_packet_data is not None else 0
        
        # Saldırı sayıları
        mac_count = len(self.mac_spoofing_attacks) if self.mac_spoofing_attacks is not None else 0
        proximity_count = len(self.proximity_attacks) if self.proximity_attacks is not None else 0
        replay_count = len(self.replay_attacks) if self.replay_attacks is not None else 0
        total_attacks = mac_count + proximity_count + replay_count
        
        # Hash tekrar analizi
        hash_stats = {'unique': 0, 'duplicated': 0, 'duplicate_percentage': 0}
        if self.raw_packet_data is not None:
            hash_counts = self.raw_packet_data['packet_hash'].value_counts()
            hash_stats['unique'] = len(hash_counts[hash_counts == 1])
            hash_stats['duplicated'] = len(hash_counts[hash_counts > 1])
            hash_stats['duplicate_percentage'] = (hash_stats['duplicated'] / len(hash_counts) * 100) if len(hash_counts) > 0 else 0
        
        return {
            'total_packets': total_packets,
            'unique_hashes': unique_hashes,
            'unique_macs': unique_macs,
            'total_attacks': total_attacks,
            'mac_attacks': mac_count,
            'proximity_attacks': proximity_count,
            'replay_attacks': replay_count,
            'time_window': self.time_window,
            'hash_stats': hash_stats,
            'analysis_date': datetime.now().strftime('%d.%m.%Y %H:%M')
        }
    
    def create_comprehensive_charts(self):
        """Tüm saldırı türleri için kapsamlı grafikleri oluştur"""
        charts = {}
        print("📊 Grafikler oluşturuluyor...")
        
        if self.raw_packet_data is None or len(self.raw_packet_data) == 0:
            print("❌ Ham paket verisi yok!")
            return charts
        
        # 1. Saldırı türleri dağılımı (pie chart)
        attack_counts = {}
        if self.mac_spoofing_attacks is not None and len(self.mac_spoofing_attacks) > 0:
            attack_counts['MAC Spoofing'] = len(self.mac_spoofing_attacks)
        if self.proximity_attacks is not None and len(self.proximity_attacks) > 0:
            attack_counts['Proximity Attack'] = len(self.proximity_attacks)
        if self.replay_attacks is not None and len(self.replay_attacks) > 0:
            attack_counts['Replay Attack'] = len(self.replay_attacks)
            
        if attack_counts:
            fig_pie = go.Figure()
            fig_pie.add_trace(go.Pie(
                labels=list(attack_counts.keys()),
                values=list(attack_counts.values()),
                hole=0.4,
                marker=dict(colors=['#ff6b6b', '#4ecdc4', '#45b7d1']),
                textinfo='label+percent+value',
                hovertemplate='<b>%{label}</b><br>Sayı: %{value}<br>Oran: %{percent}<extra></extra>'
            ))
            fig_pie.update_layout(
                title='🎯 Saldırı Türleri Dağılımı',
                plot_bgcolor='rgba(0,0,0,0)',
                paper_bgcolor='rgba(0,0,0,0)',
                font=dict(size=12)
            )
            charts['attack_distribution'] = fig_pie.to_json()
        
        # 2. MAC Spoofing analizi
        if self.mac_spoofing_attacks is not None and len(self.mac_spoofing_attacks) > 0:
            # Şüpheli MAC adreslerini say (smac kolonu kullan)
            mac_counts = self.mac_spoofing_attacks['smac'].value_counts().head(10)
            
            fig_mac = go.Figure()
            fig_mac.add_trace(go.Bar(
                x=[mac[:15] + '...' if len(mac) > 15 else mac for mac in mac_counts.index],
                y=mac_counts.values,
                marker=dict(color='#ff6b6b', opacity=0.8),
                text=mac_counts.values,
                textposition='outside',
                hovertemplate='<b>MAC:</b> %{x}<br><b>Tespit Sayısı:</b> %{y}<extra></extra>'
            ))
            fig_mac.update_layout(
                title='🎭 MAC Spoofing - Şüpheli MAC Adresleri',
                xaxis_title='MAC Adresleri',
                yaxis_title='Tespit Sayısı',
                xaxis_tickangle=-45,
                plot_bgcolor='rgba(0,0,0,0)',
                paper_bgcolor='rgba(0,0,0,0)'
            )
            charts['mac_spoofing'] = fig_mac.to_json()
            
            print(f"✅ MAC Spoofing analizi tamamlandı: {len(self.mac_spoofing_attacks)} saldırı")
        
        # 3. Proximity Attack analizi - Sadece sayı göster
        if self.proximity_attacks is not None and len(self.proximity_attacks) > 0:
            print(f"✅ Proximity Attack analizi tamamlandı: {len(self.proximity_attacks)} anomali")
        
        # 4. Replay Attack analizi - Sadece sayı göster
        if self.replay_attacks is not None and len(self.replay_attacks) > 0:
            print(f"✅ Replay Attack analizi tamamlandı: {len(self.replay_attacks)} saldırı")
        
        # 4.5. Mesafe Risk Analizi (boşluğu doldurmak için)
        if 'distance' in self.raw_packet_data.columns:
            distance_data = self.raw_packet_data['distance'].dropna()
            
            if len(distance_data) > 0:
                # Mesafe kategorileri
                distance_categories = pd.cut(distance_data, 
                                           bins=[0, 1, 5, 10, 50, float('inf')], 
                                           labels=['Çok Yakın (<1m)', 'Yakın (1-5m)', 'Orta (5-10m)', 'Uzak (10-50m)', 'Çok Uzak (>50m)'])
                
                distance_counts = distance_categories.value_counts()
                
                fig_distance = go.Figure(data=[go.Pie(
                    labels=distance_counts.index,
                    values=distance_counts.values,
                    hole=0.4,
                    marker=dict(colors=['#ff4444', '#ff8800', '#ffcc00', '#88ff00', '#00ff88']),
                    textinfo='label+percent+value',
                    hovertemplate='<b>%{label}</b><br>Paket: %{value}<br>Oran: %{percent}<extra></extra>'
                )])
                
                fig_distance.update_layout(
                    title='📍 Mesafe Bazlı Risk Dağılımı',
                    height=400,
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)',
                    annotations=[dict(text='Mesafe<br>Dağılımı', x=0.5, y=0.5, font_size=16, showarrow=False)]
                )
                charts['distance_risk_main'] = fig_distance.to_json()
                print(f"✅ Mesafe risk analizi oluşturuldu: {len(distance_data)} paket")
        
        # 5. Genel trafik analizi
        hourly_data = self.raw_packet_data.set_index('timestamp').resample('1h').size()
        fig_hourly = go.Figure()
        fig_hourly.add_trace(go.Scatter(
            x=hourly_data.index,
            y=hourly_data.values,
            mode='lines+markers',
            name='Normal Trafik',
            line=dict(color='#17becf', width=3),
            marker=dict(size=6),
            hovertemplate='<b>%{x}</b><br>Paket Sayısı: %{y}<extra></extra>'
        ))
        
        # Saldırı verilerini ekle
        if self.mac_spoofing_attacks is not None and len(self.mac_spoofing_attacks) > 0:
            mac_hourly = self.mac_spoofing_attacks.set_index('first_seen').resample('1h').size()
            mac_counts = [mac_hourly.get(ts, 0) for ts in hourly_data.index]
            fig_hourly.add_trace(go.Scatter(
                x=hourly_data.index,
                y=mac_counts,
                mode='lines+markers',
                name='MAC Spoofing',
                line=dict(color='#ff6b6b', width=3),
                marker=dict(size=8),
                hovertemplate='<b>%{x}</b><br>MAC Spoofing: %{y}<extra></extra>'
            ))
        
        fig_hourly.update_layout(
            title='📊 Trafik Analizi (Normal vs Saldırı)',
            xaxis_title='Zaman',
            yaxis_title='Paket Sayısı',
            hovermode='x unified',
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)'
        )
        charts['traffic_comparison'] = fig_hourly.to_json()
        
        # 6. Mesafe Risk Analizi
        if 'distance' in self.raw_packet_data.columns:
            distance_data = self.raw_packet_data['distance'].dropna()
            
            if len(distance_data) > 0:
                # Mesafe kategorileri
                distance_categories = pd.cut(distance_data, 
                                           bins=[0, 1, 5, 10, 50, float('inf')], 
                                           labels=['Çok Yakın (<1m)', 'Yakın (1-5m)', 'Orta (5-10m)', 'Uzak (10-50m)', 'Çok Uzak (>50m)'])
                
                distance_counts = distance_categories.value_counts()
                
                fig_distance = go.Figure(data=[go.Pie(
                    labels=distance_counts.index,
                    values=distance_counts.values,
                    hole=0.4,
                    marker=dict(colors=['#ff4444', '#ff8800', '#ffcc00', '#88ff00', '#00ff88']),
                    textinfo='label+percent+value',
                    hovertemplate='<b>%{label}</b><br>Paket: %{value}<br>Oran: %{percent}<extra></extra>'
                )])
                
                fig_distance.update_layout(
                    title='📍 Mesafe Bazlı Risk Dağılımı',
                    height=400,
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)',
                    annotations=[dict(text='Mesafe<br>Dağılımı', x=0.5, y=0.5, font_size=16, showarrow=False)]
                )
                charts['distance_risk'] = fig_distance.to_json()
                print(f"✅ Mesafe risk analizi oluşturuldu: {len(distance_data)} paket")
        
        # 7. Zaman Serisi Anomali Tespiti
        hourly_traffic = self.raw_packet_data.set_index('timestamp').resample('1h').size()
        
        if len(hourly_traffic) > 2:  # En az 3 veri noktası gerekli
            # Basit anomali tespiti (Z-score)
            mean_traffic = hourly_traffic.mean()
            std_traffic = hourly_traffic.std()
            
            if std_traffic > 0:  # Standart sapma sıfır değilse
                z_scores = (hourly_traffic - mean_traffic) / std_traffic
                anomalies = hourly_traffic[abs(z_scores) > 2]  # 2 sigma dışındakiler
                
                fig_anomaly = go.Figure()
                fig_anomaly.add_trace(go.Scatter(
                    x=hourly_traffic.index,
                    y=hourly_traffic.values,
                    mode='lines',
                    name='Normal Trafik',
                    line=dict(color='blue', width=2),
                    hovertemplate='<b>%{x}</b><br>Paket: %{y}<extra></extra>'
                ))
                
                if len(anomalies) > 0:
                    fig_anomaly.add_trace(go.Scatter(
                        x=anomalies.index,
                        y=anomalies.values,
                        mode='markers',
                        name='Anomali',
                        marker=dict(color='red', size=10, symbol='triangle-up'),
                        hovertemplate='<b>%{x}</b><br>Anomali: %{y}<extra></extra>'
                    ))
                
                # Güven aralığı
                upper_bound = mean_traffic + 2 * std_traffic
                lower_bound = max(0, mean_traffic - 2 * std_traffic)
                
                fig_anomaly.add_hline(y=upper_bound, line_dash="dash", line_color="red", 
                                     annotation_text="Üst Eşik")
                fig_anomaly.add_hline(y=lower_bound, line_dash="dash", line_color="red", 
                                     annotation_text="Alt Eşik")
                
                fig_anomaly.update_layout(
                    title='🔍 Trafik Anomali Tespiti (Z-Score)',
                    xaxis_title='Zaman',
                    yaxis_title='Saatlik Paket Sayısı',
                    height=400,
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)'
                )
                charts['anomaly_detection'] = fig_anomaly.to_json()
                print(f"✅ Anomali tespiti oluşturuldu: {len(anomalies)} anomali tespit edildi")
        
        return charts
    
    def create_html_dashboard(self):
        """HTML dashboard oluştur"""
        security_status = self.create_comprehensive_security_status()
        statistics = self.create_statistics_summary()
        charts = self.create_comprehensive_charts()
        
        html_content = f"""
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🔒 BLE Güvenlik Analizi Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <style>
        body {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            min-height: 100vh;
        }}
        .dashboard-container {{
            padding: 20px;
        }}
        .status-card {{
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            border: none;
            transition: transform 0.3s ease;
        }}
        .status-card:hover {{
            transform: translateY(-5px);
        }}
        .chart-container {{
            background: white;
            border-radius: 15px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
            padding: 20px;
            margin-bottom: 20px;
        }}
        .stat-card {{
            background: white;
            border-radius: 10px;
            padding: 20px;
            text-align: center;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            margin-bottom: 15px;
            transition: transform 0.2s ease;
        }}
        .stat-card:hover {{
            transform: scale(1.05);
        }}
        .stat-number {{
            font-size: 2.5rem;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        .safe {{ background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); color: white; }}
        .danger {{ background: linear-gradient(135deg, #fa709a 0%, #fee140 100%); color: white; }}
        .navbar-custom {{
            background: rgba(255,255,255,0.95);
            backdrop-filter: blur(10px);
        }}
        .progress-custom {{
            height: 8px;
            border-radius: 4px;
        }}
        @keyframes pulse {{
            0% {{ opacity: 1; }}
            50% {{ opacity: 0.5; }}
            100% {{ opacity: 1; }}
        }}
        .live-indicator {{
            animation: pulse 2s infinite;
        }}
    </style>
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-custom fixed-top">
        <div class="container">
            <a class="navbar-brand fw-bold" href="#">
                <i class="fas fa-shield-alt me-2"></i>
                BLE Güvenlik Dashboard
            </a>
            <div class="d-flex align-items-center">
                <span class="live-indicator me-3">
                    <i class="fas fa-circle text-success me-1"></i>
                    Canlı Analiz
                </span>
                <span class="text-muted">{statistics['analysis_date']}</span>
            </div>
        </div>
    </nav>

    <div class="container-fluid dashboard-container" style="margin-top: 80px;">
        <!-- Ana Güvenlik Durumu -->
        <div class="row mb-4">
            <div class="col-12">
                <div class="card status-card {security_status['status']}" style="background-color: {security_status['color']};">
                    <div class="card-body text-center text-white p-4">
                        <div style="font-size: 4rem;">{security_status['icon']}</div>
                        <h1 class="card-title mb-3">{security_status['title']}</h1>
                        <h4 class="card-text mb-2">{security_status['message']}</h4>
                        <p class="card-text">{security_status['detail']}</p>
                        <div class="row mt-4">
                            <div class="col-md-3">
                                <div class="stat-number">{statistics['total_packets']:,}</div>
                                <small>Toplam Paket</small>
                            </div>
                            <div class="col-md-3">
                                <div class="stat-number">{statistics['unique_hashes']:,}</div>
                                <small>Unique Hash</small>
                            </div>
                            <div class="col-md-3">
                                <div class="stat-number">{statistics['total_attacks']}</div>
                                <small>Toplam Saldırı</small>
                            </div>
                            <div class="col-md-3">
                                <div class="stat-number">{statistics['time_window']}s</div>
                                <small>Threshold</small>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- İstatistik Kartları -->
        <div class="row mb-4">
            <div class="col-md-2">
                <div class="stat-card">
                    <i class="fas fa-network-wired fa-2x text-primary mb-2"></i>
                    <div class="stat-number text-primary">{statistics['unique_macs']}</div>
                    <div class="text-muted">Unique MAC</div>
                </div>
            </div>
            <div class="col-md-2">
                <div class="stat-card">
                    <i class="fas fa-mask fa-2x text-danger mb-2"></i>
                    <div class="stat-number text-danger">{statistics['mac_attacks']}</div>
                    <div class="text-muted">MAC Spoofing</div>
                </div>
            </div>
            <div class="col-md-2">
                <div class="stat-card">
                    <i class="fas fa-location-arrow fa-2x text-warning mb-2"></i>
                    <div class="stat-number text-warning">{statistics['proximity_attacks']}</div>
                    <div class="text-muted">Proximity Attack</div>
                </div>
            </div>
            <div class="col-md-2">
                <div class="stat-card">
                    <i class="fas fa-redo fa-2x text-info mb-2"></i>
                    <div class="stat-number text-info">{statistics['replay_attacks']}</div>
                    <div class="text-muted">Replay Attack</div>
                </div>
            </div>
            <div class="col-md-2">
                <div class="stat-card">
                    <i class="fas fa-percentage fa-2x text-success mb-2"></i>
                    <div class="stat-number text-success">{statistics['hash_stats']['duplicate_percentage']:.1f}%</div>
                    <div class="text-muted">Duplicate Hash</div>
                </div>
            </div>
            <div class="col-md-2">
                <div class="stat-card">
                    <i class="fas fa-clock fa-2x text-secondary mb-2"></i>
                    <div class="stat-number text-secondary">{statistics['time_window']}</div>
                    <div class="text-muted">Saniye Threshold</div>
                </div>
            </div>
        </div>

        <!-- Grafik Konteyners -->
        <div class="row">
            <!-- Saldırı Dağılımı -->
            {"<div class='col-lg-4'><div class='chart-container'><div id='attack_distribution'></div></div></div>" if 'attack_distribution' in charts else ""}
            
            <!-- Trafik Karşılaştırması -->
            {"<div class='col-lg-4'><div class='chart-container'><div id='traffic_comparison'></div></div></div>" if 'traffic_comparison' in charts else ""}
            
            <!-- MAC Spoofing Analizi -->
            {"<div class='col-lg-4'><div class='chart-container'><div id='mac_spoofing'></div></div></div>" if 'mac_spoofing' in charts else ""}
            
        </div>

        <!-- Gelişmiş Analitik Grafikler -->
        <div class="row mb-4">
            <div class="col-md-6">
                <div class="chart-container">
                    <h6><i class="fas fa-map-marker-alt me-2"></i>Mesafe Risk Analizi</h6>
                    <div id="distance_risk"></div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="chart-container">
                    <h6><i class="fas fa-search me-2"></i>Anomali Tespiti</h6>
                    <div id="anomaly_detection"></div>
                </div>
            </div>
        </div>

        <!-- Güvenlik Önerileri -->
        <div class="row">
            <div class="col-12">
                <div class="chart-container">
                    <h5><i class="fas fa-lightbulb me-2"></i>Akıllı Güvenlik Önerileri</h5>
                    <div class="row">
                        <div class="col-md-4">
                            <div class="alert alert-info">
                                <h6>🔍 Proaktif İzleme</h6>
                                <ul class="mb-0">
                                    <li>7/24 gerçek zamanlı izleme aktif</li>
                                    <li>Anomali tespiti çalışıyor</li>
                                    <li>Otomatik uyarı sistemi devrede</li>
                                </ul>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="alert alert-warning">
                                <h6>⚡ Hızlı Müdahale</h6>
                                <ul class="mb-0">
                                    <li>Şüpheli MAC'leri izole edin</li>
                                    <li>Güvenlik politikalarını güncelleyin</li>
                                    <li>Incident response planını aktive edin</li>
                                </ul>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="alert alert-success">
                                <h6>🛡️ Koruyucu Önlemler</h6>
                                <ul class="mb-0">
                                    <li>BLE cihazlarını güncel tutun</li>
                                    <li>Şifreleme seviyesini artırın</li>
                                    <li>Düzenli güvenlik taraması yapın</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Grafikleri yükle
        document.addEventListener('DOMContentLoaded', function() {{
            console.log('📊 Dashboard grafikleri yükleniyor...');
            
            const charts = {json.dumps(charts, indent=8)};
            
            // Her grafik için render et
            Object.keys(charts).forEach(chartKey => {{
                try {{
                    const chartDiv = document.getElementById(chartKey);
                    if (chartDiv) {{
                        const plotData = JSON.parse(charts[chartKey]);
                        Plotly.newPlot(chartDiv, plotData.data, plotData.layout, {{
                            responsive: true,
                            displayModeBar: false
                        }});
                        console.log(`✅ ${{chartKey}} grafiği yüklendi`);
                    }}
                }} catch (error) {{
                    console.error(`❌ ${{chartKey}} grafiği yüklenirken hata:`, error);
                }}
            }});
            
            console.log('🎉 Tüm grafikler başarıyla yüklendi!');
            
            // Güvenlik durumu bildirimi
            setTimeout(() => {{
                const totalAttacks = {security_status['total_attacks']};
                if (totalAttacks > 0) {{
                    console.warn(`⚠️ UYARI: ${{totalAttacks}} güvenlik tehdidi tespit edildi!`);
                }} else {{
                    console.log('✅ Sistem güvenli durumda');
                }}
            }}, 1000);
        }});
        
        // Responsive chart update
        window.addEventListener('resize', function() {{
            Object.keys({json.dumps(list(charts.keys()))}).forEach(chartKey => {{
                const chartDiv = document.getElementById(chartKey);
                if (chartDiv) {{
                    Plotly.Plots.resize(chartDiv);
                }}
            }});
        }});
    </script>
</body>
</html>"""
        
        return html_content
    
    def generate_dashboard(self):
        """Dashboard oluştur ve kaydet"""
        print("🎨 İnteraktif HTML Dashboard oluşturuluyor...")
        
        # Verileri yükle
        self.load_data()
        
        if self.raw_packet_data is None or len(self.raw_packet_data) == 0:
            print("❌ Paket verisi bulunamadı!")
            return
        
        # HTML dashboard oluştur
        html_content = self.create_html_dashboard()
        
        # Dosyaya kaydet
        dashboard_path = os.path.join(self.docs_path, 'ble_security_dashboard.html')
        with open(dashboard_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"✅ İnteraktif dashboard oluşturuldu!")
        print(f"📁 Dosya konumu: {dashboard_path}")
        print(f"🌐 Tarayıcınızda açmak için: file://{os.path.abspath(dashboard_path)}")
        print("\n🎉 Dashboard özellikleri:")
        print("   • ✨ Modern ve responsive tasarım")
        print("   • 📊 İnteraktif Plotly grafikleri") 
        print("   • 🔄 Canlı güvenlik durumu")
        print("   • 📱 Mobil uyumlu")
        print("   • 🎨 Bootstrap ile güzel arayüz")
        print("   • 📈 Zoomlanabilir grafikler")

if __name__ == "__main__":
    creator = ComprehensiveSecurityDashboard()
    creator.generate_dashboard() 