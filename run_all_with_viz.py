import subprocess
import sys

# List of scripts to run in order
analysis_scripts = [
    # "logs_to_db.py",
    # "insertMockedData.py",
    # "dbExport.py", 
    # "macSpoof.py",
    # "proximityAlert.py",
    # "replayAttack.py",
    # "create_interactive_dashboard.py",
    "visualize_mac_spoofing.py",
    "visualize_proximity_alert.py",
    "visualize_replay_attack.py",
    
]

visualization_scripts = [    "visualize_complete.py"]

print("🚀 BLE Güvenlik Analizi ve Görselleştirme Pipeline'ı Başlatılıyor...\n")

# İlk olarak analiz scriptlerini çalıştır
print("📊 ADIM 1: BLE Güvenlik Analizi")
print("=" * 50)

for script in analysis_scripts:
    print(f"▶️ {script} çalıştırılıyor...")
    result = subprocess.run(["python", script])
    if result.returncode != 0:
        print(f"❌ {script} başarısız oldu (hata kodu: {result.returncode}). Pipeline durduruluyor.")
        sys.exit(1)
    print(f"✅ {script} başarıyla tamamlandı.\n")

print("🎨 ADIM 2: Görselleştirme ve Dashboard Oluşturma")
print("=" * 50)

# Sonra görselleştirme scriptlerini çalıştır
for script in visualization_scripts:
    print(f"▶️ {script} çalıştırılıyor...")
    result = subprocess.run(["python", script])
    if result.returncode != 0:
        print(f"⚠️ {script} başarısız oldu (hata kodu: {result.returncode}). Analiz tamamlandı ancak görselleştirme oluşturulamadı.")
    else:
        print(f"✅ {script} başarıyla tamamlandı.\n")

print("🎉 Pipeline tamamlandı!")
print("\n📋 Oluşturulan Çıktılar:")
print("   📁 ./Docs/ klasöründe:")
print("      • CSV analiz dosyaları")
print("      • PNG grafik dosyaları")
print("      • TXT özet istatistik raporu")