# config.py
import os

# === File Paths ===
# Base output directory
OUTPUT_DIR = './outputs'

# Specific paths
DB_PATH = os.path.join(OUTPUT_DIR, 'DB', 'Bledb.db')
DOCS_DIR = os.path.join(OUTPUT_DIR, 'Docs')
FOTOS_DIR = os.path.join(OUTPUT_DIR, 'images')
PCAP_FILE = os.path.join('wireLogs', 'watch_capture.pcapng')

# Ensure output directories exist (optional helper)
def ensure_output_dirs():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    os.makedirs(DOCS_DIR, exist_ok=True)
    os.makedirs(FOTOS_DIR, exist_ok=True)
    
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
