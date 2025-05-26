import hashlib
from config import RSSI_REFERENCE, ENVIRONMENTAL_FACTOR

def rssi_to_distance(rssi, p0=RSSI_REFERENCE, n=ENVIRONMENTAL_FACTOR):
    try:
        return round(10 ** ((p0 - int(rssi)) / (10 * n)), 2)
    except:
        return None

def generate_packet_hash(fields):
    combined = f"{fields['timestamp']}_{fields['dmac']}_{fields['uuids_16']}_{fields['uuids_32']}_{fields['uuids_128']}_{fields['company_id']}_{fields['manufacturer_data']}_{fields['rssi']}"
    return hashlib.sha256(combined.encode()).hexdigest()
