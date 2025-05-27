import sqlite3
import pandas as pd
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from config import DB_PATH, DOCS_DIR

def ensure_export_dir(path):
    os.makedirs(path, exist_ok=True)

def export_ble_packet(conn, export_path):
    try:
        df = pd.read_sql_query("SELECT * FROM BLEPacket", conn)
        df.to_csv(os.path.join(export_path, "BLEPacket.csv"), index=False)
        print("✔️ BLEPacket.csv created.")
    except Exception as e:
        print(f"❌ BLEPacket.csv error: {e}")

def export_ble_packet_uuid(conn, export_path):
    try:
        df = pd.read_sql_query("""
            SELECT 
                BLEPacketUUID.id,
                BLEPacketUUID.ble_packet_id,
                BLEPacket.timestamp,
                BLEPacket.smac,
                BLEPacketUUID.uuid_type,
                BLEPacketUUID.uuid
            FROM BLEPacketUUID
            JOIN BLEPacket ON BLEPacket.id = BLEPacketUUID.ble_packet_id
        """, conn)
        df.to_csv(os.path.join(export_path, "BLEPacketUUID.csv"), index=False)
        print("✔️ BLEPacketUUID.csv created.")
    except Exception as e:
        print(f"❌ BLEPacketUUID.csv error: {e}")

def export_joined_data(conn, export_path):
    try:
        df = pd.read_sql_query("""
            SELECT 
                BLEPacket.timestamp,
                BLEPacket.smac,
                BLEPacket.dmac,
                BLEPacket.rssi,
                BLEPacket.distance,
                BLEPacket.company_id,
                BLEPacket.manufacturer_data,
                BLEPacket.packet_hash,
                GROUP_CONCAT(BLEPacketUUID.uuid || ' (' || BLEPacketUUID.uuid_type || ')', '; ') AS uuids
            FROM BLEPacket
            LEFT JOIN BLEPacketUUID ON BLEPacket.id = BLEPacketUUID.ble_packet_id
            GROUP BY BLEPacket.id
            ORDER BY BLEPacket.timestamp
        """, conn)
        df.to_csv(os.path.join(export_path, "BLEPacket_Joined.csv"), index=False)
        print("✔️ BLEPacket_Joined.csv created.")
    except Exception as e:
        print(f"❌ BLEPacket_Joined.csv error: {e}")

def export_all():
    ensure_export_dir(DOCS_DIR)
    conn = sqlite3.connect(DB_PATH)

    export_ble_packet(conn, DOCS_DIR)
    export_ble_packet_uuid(conn, DOCS_DIR)
    export_joined_data(conn, DOCS_DIR)

    conn.close()
    print("✅ All exports completed successfully.")

export_all()