import sqlite3
import pandas as pd
from datetime import datetime, timedelta
import os
from config import DB_PATH, DOCS_DIR, REPLAY_TIME_WINDOW_SEC

def ensure_output_dir(path):
    os.makedirs(path, exist_ok=True)

def load_packet_hash_data(db_path):
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query("""
        SELECT timestamp, dmac, smac, rssi, distance, packet_hash
        FROM BLEPacket
        ORDER BY timestamp
    """, conn)
    conn.close()

    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    return df

def detect_replay_attacks(df, replay_window_sec):
    alerts = []
    window = timedelta(seconds=replay_window_sec)

    for packet_hash, group in df.groupby('packet_hash'):
        if len(group) <= 1:
            continue

        group = group.sort_values('timestamp')
        timestamps = group['timestamp'].tolist()

        for i in range(1, len(timestamps)):
            delta = timestamps[i] - timestamps[i - 1]
            if delta < window:
                alerts.append({
                    'packet_hash': packet_hash,
                    'first_seen': timestamps[i - 1],
                    'repeated_at': timestamps[i],
                    'time_diff_secs': delta.total_seconds(),
                    'repetition_count': len(group),
                    'dmac': group.iloc[i]['dmac'],
                    'smac': group.iloc[i]['smac'],
                    'rssi': group.iloc[i]['rssi'],
                    'distance': group.iloc[i]['distance']
                })
                break  # One alert per packet hash
    return alerts

def save_alerts(alerts, output_path):
    df = pd.DataFrame(alerts)
    df.to_csv(output_path, index=False)
    print(f"✔️ {len(df)} replay attack(s) logged in {output_path}.")

def main():
    ensure_output_dir(DOCS_DIR)
    df = load_packet_hash_data(DB_PATH)
    alerts = detect_replay_attacks(df, REPLAY_TIME_WINDOW_SEC)
    save_alerts(alerts, os.path.join(DOCS_DIR, "ReplayAttackAlerts.csv"))

if __name__ == "__main__":
    main()
