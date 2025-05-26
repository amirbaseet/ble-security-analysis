import sqlite3
import pandas as pd
import os
from config import DB_PATH, DOCS_DIR

def ensure_output_dir():
    os.makedirs(DOCS_DIR, exist_ok=True)

def load_data():
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("""
        SELECT 
        BLEPacket.id,
        BLEPacket.timestamp,
        BLEPacket.dmac,
        BLEPacket.smac,
        BLEPacket.rssi,
        BLEPacket.distance,
        BLEPacket.company_id,
        BLEPacket.manufacturer_data,
        BLEPacket.packet_hash,
        BLEPacketUUID.uuid_type,
        BLEPacketUUID.uuid
        FROM BLEPacket
        LEFT JOIN BLEPacketUUID ON BLEPacket.id = BLEPacketUUID.ble_packet_id
    """, conn)
    conn.close()
    return df

def normalize_data(df):
    df['timestamp'] = pd.to_datetime(df['timestamp'], format='ISO8601', errors='coerce')
    df['dmac'] = df['dmac'].str.lower()
    df['smac'] = df['smac'].str.lower()
    df['company_id'] = df['company_id'].fillna('')
    df['manufacturer_data'] = df['manufacturer_data'].fillna('')
    df['uuid'] = df['uuid'].fillna('')
    df['uuid_type'] = df['uuid_type'].fillna('')
    df['packet_hash'] = df['packet_hash'].fillna('')
    df['rssi'] = pd.to_numeric(df['rssi'], errors='coerce').fillna(0)
    df['distance'] = pd.to_numeric(df['distance'], errors='coerce').fillna(0)
    return df

def generate_fingerprints(df):
    df['fingerprint'] = (
        # df['company_id'].astype(str) + '|' +
        # df['manufacturer_data'].astype(str) + '|' +
        df['uuid_type'].astype(str) 
        + ':' + df['uuid'].astype(str)
        #making it less sensetive 
        #   + '|' +
        # df['rssi'].astype(str) + '|' +
        # df['distance'].astype(str)
    )
    return df

def detect_fingerprint_changes(df):
    df_sorted = df.sort_values(['smac', 'timestamp'])
    df_sorted['prev_fingerprint'] = df_sorted.groupby('smac')['fingerprint'].shift()
    df_sorted['fingerprint_changed'] = df_sorted['fingerprint'] != df_sorted['prev_fingerprint']
    return df_sorted[df_sorted['fingerprint_changed'] & df_sorted['prev_fingerprint'].notnull()]

def detect_packet_hash_anomalies(df):
    return df.groupby('smac')['packet_hash'].nunique().reset_index(name='hash_variants')

def detect_rssi_distance_anomalies(df, rssi_thresh=25, dist_thresh=10):
    df_sorted = df.sort_values(['smac', 'timestamp'])
    df_sorted['prev_rssi'] = df_sorted.groupby('smac')['rssi'].shift()
    df_sorted['prev_distance'] = df_sorted.groupby('smac')['distance'].shift()
    df_sorted['rssi_diff'] = abs(df_sorted['rssi'] - df_sorted['prev_rssi'])
    df_sorted['distance_diff'] = abs(df_sorted['distance'] - df_sorted['prev_distance'])
    anomalies = df_sorted[
        ((df_sorted['rssi_diff'] > rssi_thresh) | 
         (df_sorted['distance_diff'] > dist_thresh)) & 
        df_sorted['prev_rssi'].notnull()
    ]
    return anomalies

def generate_statistics(df):
    fingerprint_counts = df.groupby('smac')['fingerprint'].nunique().reset_index()
    fingerprint_counts.columns = ['smac', 'unique_fingerprints']

    heuristic_stats = df.groupby('smac').agg({
        'dmac': pd.Series.nunique,
        'timestamp': ['min', 'max', 'count']
    }).reset_index()
    heuristic_stats.columns = ['smac', 'unique_dmacs', 'first_seen', 'last_seen', 'packet_count']

    return fingerprint_counts, heuristic_stats

def generate_alerts(fingerprint_counts, heuristic_stats, hash_anomalies):
    merged = pd.merge(fingerprint_counts, heuristic_stats, on='smac', how='outer').fillna(0)
    merged = pd.merge(merged, hash_anomalies, on='smac', how='left')
    merged['hash_anomaly'] = merged['hash_variants'].fillna(1) > 1
    merged['fingerprint_anomaly'] = merged['unique_fingerprints'] > 1
    merged['dmac_anomaly'] = merged['unique_dmacs'] > 1

    alerts = merged[
        (merged['fingerprint_anomaly']) |
        (merged['dmac_anomaly']) |
        (merged['hash_anomaly'])
    ].copy()
    return alerts, merged

def export_top_patterns(df):
    top_uuids = df['uuid'].value_counts().head(10).reset_index()
    top_uuids.columns = ['uuid', 'count']
    top_uuids.to_csv(os.path.join(DOCS_DIR, "Top_UUIDs.csv"), index=False)

    top_manufacturers = df['manufacturer_data'].value_counts().head(10).reset_index()
    top_manufacturers.columns = ['manufacturer_data', 'count']
    top_manufacturers.to_csv(os.path.join(DOCS_DIR, "Top_ManufacturerData.csv"), index=False)

def save_csvs(fingerprint_change_events, alerts, rssi_distance_anomalies):
    fingerprint_change_events[['smac', 'timestamp', 'prev_fingerprint', 'fingerprint']].to_csv(
        os.path.join(DOCS_DIR, "Fingerprint_Change_Events.csv"), index=False)
    print("📌 Fingerprint_Change_Events.csv kaydedildi.")

    alerts.sort_values('packet_count', ascending=False, inplace=True)
    alerts.to_csv(os.path.join(DOCS_DIR, "MACSpoofing_CombinedAlerts.csv"), index=False)
    print("✔️ MACSpoofing_CombinedAlerts.csv dosyası oluşturuldu.")

    rssi_distance_anomalies[['smac', 'timestamp', 'rssi', 'prev_rssi', 'rssi_diff', 'distance', 'prev_distance', 'distance_diff']].to_csv(
        os.path.join(DOCS_DIR, "RSSI_Distance_Anomalies.csv"), index=False)
    print("⚠️ RSSI_Distance_Anomalies.csv kaydedildi.")

    print("📌 Top_UUIDs.csv ve Top_ManufacturerData.csv oluşturuldu.")

def main():
    ensure_output_dir()
    df = load_data()
    df = normalize_data(df)
    df = generate_fingerprints(df)

    fingerprint_change_events = detect_fingerprint_changes(df)
    fingerprint_counts, heuristic_stats = generate_statistics(df)
    hash_anomalies = detect_packet_hash_anomalies(df)
    rssi_distance_anomalies = detect_rssi_distance_anomalies(df)

    alerts, merged = generate_alerts(fingerprint_counts, heuristic_stats, hash_anomalies)

    export_top_patterns(df)
    save_csvs(fingerprint_change_events, alerts, rssi_distance_anomalies)

if __name__ == "__main__":
    main()
