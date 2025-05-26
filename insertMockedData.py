import pyshark
import sqlite3
from collections import defaultdict
from config import DB_PATH
from utils.db_utils import insert_malicious_attack_data, verify_malicious_data, init_db, insert_packet, insert_uuids, insert_spoof_alert

def main():
    """Ana fonksiyon - saldırı verilerini veritabanına ekler"""
    print("🚀 Saldırı simülasyon verileri ekleme işlemi başlatılıyor...")
    
    try:
        # Veritabanını başlat
        print("📊 Veritabanı bağlantısı kuruluyor...")
        conn, cursor = init_db(DB_PATH)
        conn.close()
        
        # Saldırı verilerini ekle
        print("🚨 Saldırı verilerini ekleniyor...")
        insert_malicious_attack_data(DB_PATH)
        
        # Verileri doğrula
        print("🔍 Veriler doğrulanıyor...")
        verify_malicious_data(DB_PATH)
        
        print("✅ İşlem başarıyla tamamlandı!")
        
    except Exception as e:
        print(f"❌ Hata oluştu: {e}")
        print(f"Hata türü: {type(e).__name__}")

if __name__ == "__main__":
    main()