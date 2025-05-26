# config.py

# === File Paths ===
DB_PATH = './DB/BLETrace.db'
PCAP_FILE = './wireLogs/fakulte.pcapng'
DOCS_DIR = './Docs'
FOTOS_DIR = './fotos/'
JSON_FILE = "./wireLogs/ble_packets.json"
REPLAY_TIME_WINDOW_SEC = 5
# === BLE Distance Estimation Parameters ===
RSSI_REFERENCE = -59  # Measured RSSI at 1 meter
ENVIRONMENTAL_FACTOR = 2  # Path-loss exponent (1.6–3.3 typical)

# === Hashing Fields (for traceability if needed later) ===
USE_HASH_FIELDS = [
    'timestamp', 'dmac', 'uuids_16', 'uuids_32', 'uuids_128',
    'company_id', 'manufacturer_data', 'rssi'
]

# Configuration settings for BLE Analysis Project

# Output directory for analysis results
DOCS_DIR = './Docs/'

# Visualization settings
VISUALIZATION_DPI = 300
FIGURE_SIZE = (15, 10)

# Analysis thresholds
FINGERPRINT_CHANGE_THRESHOLD = 1
DMAC_ANOMALY_THRESHOLD = 1
PACKET_COUNT_THRESHOLD = 10

# Colors for visualization
COLORS = {
    'primary': '#1f77b4',
    'danger': '#d62728', 
    'warning': '#ff7f0e',
    'success': '#2ca02c',
    'info': '#17becf',
    'purple': '#9467bd'
}
