import subprocess
import sys
from config import OUTPUT_DIR, ensure_output_dirs

# Ensure necessary directories exist
ensure_output_dirs()

# List of scripts to run in order
analysis_scripts = [
    "scripts/logs_to_db.py",
    "scripts/insertMockedData.py",
    "scripts/dbExport.py", 
    "scripts/macSpoof.py",
    "scripts/proximityAlert.py",
    "scripts/replayAttack.py",
    "scripts/create_interactive_dashboard.py",
    "visualizations/visualize_mac_spoofing.py",
    "visualizations/visualize_proximity_alert.py",
    "visualizations/visualize_replay_attack.py",
]

visualization_scripts = [
    "visualize_complete.py"
]

print("🚀 BLE Güvenlik Analizi ve Görselleştirme Pipeline'ı Başlatılıyor...\n")

# First, run the analysis scripts
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

# Then run the visualization scripts
for script in visualization_scripts:
    print(f"▶️ {script} çalıştırılıyor...")
    result = subprocess.run(["python", script])
    if result.returncode != 0:
        print(f"⚠️ {script} başarısız oldu (hata kodu: {result.returncode}). Analiz tamamlandı ancak görselleştirme oluşturulamadı.")
    else:
        print(f"✅ {script} başarıyla tamamlandı.\n")

print("🎉 Pipeline tamamlandı!")
print("\n📋 Oluşturulan Çıktılar:")
print("   📁 ./outputs/ klasöründe:")
print("      • Docs/CSV analiz dosyaları")
print("      • images/PNG grafik dosyaları")
print("      • Docs/TXT özet istatistik raporu")
