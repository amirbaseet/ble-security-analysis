import sqlite3
import pandas as pd
import numpy as np
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from config import DB_PATH, DOCS_DIR

# === Parameters ===
DISTANCE_THRESHOLD_M = 40      # meters
MIN_TIME_WINDOW_SEC = 1        # seconds



def load_distance_data(db_path):
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query("""
        SELECT timestamp, smac, distance
        FROM BLEPacket
        WHERE distance IS NOT NULL
        ORDER BY smac, timestamp
    """, conn)
    conn.close()
    
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    df['smac'] = df['smac'].str.lower()
    
    # Hatalı timestamp'leri temizle
    df = df.dropna(subset=['timestamp'])
    
    return df

def detect_proximity_anomalies_ultra_fast(df, distance_threshold=DISTANCE_THRESHOLD_M, min_window=MIN_TIME_WINDOW_SEC):
    """Ultra-optimized version with minimal loops"""
    
    # Sort and prepare data
    df = df.sort_values(['smac', 'timestamp']).reset_index(drop=True)
    df['delta'] = df.groupby('smac')['timestamp'].diff().dt.total_seconds()
    
    # Pre-calculate time windows for each smac
    smac_windows = {}
    for smac, group in df.groupby('smac'):
        avg_interval = group['delta'].mean()
        if pd.isna(avg_interval):
            avg_interval = min_window
        smac_windows[smac] = max(min_window, avg_interval * 2)
    
    # Convert timestamps to numeric for faster comparison
        df['ts_numeric'] = df['timestamp'].astype('int64') // 10**9
    
    anomalies = []
    
    # Group processing with batch operations
    for smac, group in df.groupby('smac'):
        if len(group) < 2:
            continue
            
        group = group.reset_index(drop=True)
        time_window_sec = smac_windows[smac]
        
        n = len(group)
        ts_vals = group['ts_numeric'].values
        dist_vals = group['distance'].values
        timestamp_vals = group['timestamp'].values
        
        # Create distance difference matrix (vectorized)
        dist_matrix = np.abs(dist_vals[:, np.newaxis] - dist_vals[np.newaxis, :])
        
        # Create time difference matrix (vectorized)
        time_matrix = ts_vals[:, np.newaxis] - ts_vals[np.newaxis, :]
        
        # Find valid pairs (within time window and distance threshold)
        valid_pairs = (
            (time_matrix > 0) & 
            (time_matrix <= time_window_sec) & 
            (dist_matrix >= distance_threshold)
        )
        
        # Extract anomaly pairs
        i_indices, j_indices = np.where(valid_pairs)
        
        for i, j in zip(i_indices, j_indices):
            anomalies.append({
                'smac': smac,
                'timestamp_1': timestamp_vals[i],
                'distance_1': dist_vals[i],
                'timestamp_2': timestamp_vals[j],
                'distance_2': dist_vals[j],
                'distance_diff': dist_matrix[i, j],
                'time_window_sec': time_window_sec
            })
    
    return anomalies

def save_anomalies(anomalies, output_file):
    if not anomalies:
        print("✔️ No anomalies found.")
        return
        
    df = pd.DataFrame(anomalies)
    df.to_csv(output_file, index=False)
    print(f"✔️ {len(df)} anomaly(ies) logged in {output_file}.")

def main():
    
    print("Loading data...")
    df = load_distance_data(DB_PATH)
    print(f"Loaded {len(df)} records.")
    
    print("Detecting anomalies (ultra-fast)...")
    anomalies = detect_proximity_anomalies_ultra_fast(df)
    
    save_anomalies(anomalies, os.path.join(DOCS_DIR, "ProximityAnomalyAlerts.csv"))

if __name__ == "__main__":
    main()
