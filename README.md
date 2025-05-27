

This repository contains a collection of Python scripts for analyzing and visualizing **Bluetooth Low Energy (BLE) security events** such as:

- 🕵️ **MAC Spoofing** detection and analysis
- 📍 **Proximity Anomaly** detection and analysis
- 🔄 **Replay Attack** detection and analysis

Each script generates detailed visualizations and summary reports based on analysis results.

---

## 🚀 Features

| Feature                       | Scripts                     | Visualizations                                               | Reports                            |
|------------------------------|----------------------------|-------------------------------------------------------------|---------------------------------------|
| 🔐 MAC Spoofing Detection     | `visualize_mac_spoofing.py` | Fingerprint change analysis, anomaly dashboard, pattern analysis | `mac_spoofing_summary.txt`     |
| 📡 Proximity Anomaly Detection | `visualize_proximity_alert.py` | Distance analysis, anomaly dashboard, temporal patterns        | `proximity_alert_summary.txt`|
| 🛡️ Replay Attack Detection    | `visualize_replay_attack.py` | Packet analysis, replay attack dashboard, security timeline    | `replay_attack_summary.txt`     |

All scripts save graphs in the `FOTOS_DIR` and reports in the `DOCS_DIR` directories.

---

## 🧩 Requirements

- Python 3.7+
- `pandas`
- `matplotlib`
- `seaborn`
- `numpy`
- `sqlite3` (for database access)
- `config.py` file with the following structure:

```python
# config.py (example)
DB_PATH = '/path/to/your/database.db'
DOCS_DIR = '/path/to/docs/'
FOTOS_DIR = '/path/to/images/'
PCAP_FILE = '/path/to/wireSharkFiles/'
REPLAY_TIME_WINDOW_SEC = 300  # For replay attack detection threshold
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---
## 🗃️ Required Files
- wireLogs/: Place your .pcap or .pcapng BLE logs here.
- Example: wireLogs/your_ble_capture.pcapng
- The project requires at least one BLE capture file to process.

## 🏗️ Usage

1️⃣ Prepare your **SQLite BLE database** and related CSV files:
- `Fingerprint_Change_Events.csv`
- `MacSpoofingAlerts.csv`
- `Top_UUIDs.csv`
- `Top_ManufacturerData.csv`
- `ProximityAnomalyAlerts.csv`
- `ReplayAttackAlerts.csv`

2️⃣ Set the correct paths in `config.py`.

3️⃣ Run the desired visualization script:

```bash
python visualize_mac_spoofing.py
python visualize_proximity_alert.py
python visualize_replay_attack.py
```

4️⃣ Check the generated visualizations and summary reports in the specified directories.

---

## 🖼️ Sample Outputs

- 📊 **MAC Spoofing**: `mac_spoofing_fingerprint_analysis.png`, `mac_spoofing_anomaly_dashboard.png`
- 📊 **Proximity Alert**: `proximity_distance_analysis.png`, `proximity_anomaly_dashboard.png`
- 📊 **Replay Attack**: `replay_packet_analysis.png`, `replay_attack_dashboard.png`

---

## 📬 Contact

For questions, feedback, or contributions, feel free to reach out!
