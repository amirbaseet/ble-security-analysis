import sqlite3
from datetime import datetime

def init_db(db_path):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    c.execute('''
    CREATE TABLE IF NOT EXISTS BLEPacket (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        smac TEXT,
        dmac TEXT,
        rssi INTEGER,
        distance REAL,
        company_id TEXT,
        manufacturer_data TEXT,
        packet_hash TEXT
    )''')

    c.execute('''
    CREATE TABLE IF NOT EXISTS BLEPacketUUID (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ble_packet_id INTEGER,
        uuid_type TEXT,
        uuid TEXT,
        FOREIGN KEY (ble_packet_id) REFERENCES BLEPacket(id)
    )''')

    c.execute('''
    CREATE TABLE IF NOT EXISTS MACSpoofingAlerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        uuid_type TEXT,
        uuid TEXT,
        company_id TEXT,
        manufacturer_data TEXT,
        conflicting_macs TEXT
    )''')

    conn.commit()
    return conn, c

def insert_packet(cursor, conn, entry):
    cursor.execute('''
        INSERT OR IGNORE INTO BLEPacket 
        (timestamp, smac, dmac, rssi, distance, company_id, manufacturer_data, packet_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        entry['timestamp'], entry['smac'], entry['dmac'], entry['rssi'],
        entry['distance'], entry['company_id'], entry['manufacturer_data'], entry['packet_hash']
    ))
    conn.commit()
    return cursor.lastrowid

def insert_uuids(cursor, conn, packet_id, uuids, uuid_type):
    for uuid in uuids:
        cursor.execute('''
    INSERT INTO BLEPacketUUID (ble_packet_id, uuid_type, uuid) VALUES (?, ?, ?)
        ''', (packet_id, uuid_type, uuid))
    conn.commit()

def insert_spoof_alert(cursor, conn, alert):
    cursor.execute('''
        INSERT INTO MACSpoofingAlerts 
        (timestamp, uuid_type, uuid, company_id, manufacturer_data, conflicting_macs)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (
        alert['timestamp'], alert['uuid_type'], alert['uuid'], 
        alert['company_id'], alert['manufacturer_data'], 
        ', '.join(alert['conflicting_macs'])
    ))
    conn.commit()

def insert_malicious_attack_data(db_path):
    """
    Güvenilir olmayan ağ ortamını simüle eden saldırı verilerini ekler
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    print("🚨 Saldırı simülasyon verileri ekleniyor...")
    
    # Saldırı simülasyon verileri
    malicious_packets=[
  {
    "id": 1,
    "timestamp": "2025-05-26 15:00:00.000000",
    "smac": "AA:BB:CC:DD:EE:FF",
    "dmac": "FF:FF:FF:FF:FF:FF",
    "rssi": -40,
    "distance": 1.0,
    "company_id": "0x0006",
    "manufacturer_data": "01:09:21:0a:83:a0:ee:20:45:48",
    "packet_hash": "replayhash1",
    "uuids_16": ["0xfdee"],
    "uuids_32": [],
    "uuids_128": []
  },
  {
    "id": 2,
    "timestamp": "2025-05-26 15:00:01.000000",
    "smac": "AA:BB:CC:DD:EE:FF",
    "dmac": "FF:FF:FF:FF:FF:FF",
    "rssi": -40,
    "distance": 1.0,
    "company_id": "0x0006",
    "manufacturer_data": "01:09:21:0a:83:a0:ee:20:45:48",
    "packet_hash": "replayhash1",
    "uuids_16": ["0xfdee"],
    "uuids_32": [],
    "uuids_128": []
  },
  {
    "id": 3,
    "timestamp": "2025-05-26 15:01:00.000000",
    "smac": "11:22:33:44:55:66",
    "dmac": "FF:FF:FF:FF:FF:FF",
    "rssi": -35,
    "distance": 0.8,
    "company_id": "0x0006",
    "manufacturer_data": "01:09:21:0a:83:a0:ee:20:45:48",
    "packet_hash": "proximityhash1",
    "uuids_16": ["0xfeed"],
    "uuids_32": [],
    "uuids_128": []
  },
  {
    "id": 4,
    "timestamp": "2025-05-26 15:02:00.000000",
    "smac": "11:22:33:44:55:66",
    "dmac": "FF:FF:FF:FF:FF:FF",
    "rssi": -30,
    "distance": 0.5,
    "company_id": "0x0006",
    "manufacturer_data": "01:09:21:0a:83:a0:ee:20:45:48",
    "packet_hash": "proximityhash2",
    "uuids_16": ["0xfeed"],
    "uuids_32": [],
    "uuids_128": []
  },
  {
    "id": 5,
    "timestamp": "2025-05-26 15:05:00.000000",
    "smac": "27:DF:D0:83:01:3F",
    "dmac": "FF:FF:FF:FF:FF:FF",
    "rssi": -45,
    "distance": 2.0,
    "company_id": "0x0006",
    "manufacturer_data": "01:09:21:0a:83:a0:ee:20:45:48:44:45:53:4b:54:4f:50:2d:45:48:33:33:54:31:35",
    "packet_hash": "spoofhash1",
    "uuids_16": ["0xabcd"],
    "uuids_32": [],
    "uuids_128": []
  },
  {
    "id": 6,
    "timestamp": "2025-05-26 15:05:01.000000",
    "smac": "69:84:17:7F:FD:D9",
    "dmac": "FF:FF:FF:FF:FF:FF",
    "rssi": -45,
    "distance": 2.0,
    "company_id": "0x0006",
    "manufacturer_data": "01:09:21:0a:83:a0:ee:20:45:48:44:45:53:4b:54:4f:50:2d:45:48:33:33:54:31:35",
    "packet_hash": "spoofhash1",
    "uuids_16": ["0xabcd"],
    "uuids_32": [],
    "uuids_128": []
  },
      {
        "id": 7,
        "timestamp": "2025-05-26 15:06:00.000000",
        "smac": "DE:AD:BE:EF:00:01",
        "dmac": "FF:FF:FF:FF:FF:FF",
        "rssi": -50,
        "distance": 2.5,
        "company_id": "0x004C",  # Apple Inc.
        "manufacturer_data": "4C000215A495B7C5FF8A7D7F811DAB",  # iBeacon format
        "packet_hash": "beaconflood1",
        "uuids_16": ["0xfeed"],
        "uuids_32": [],
        "uuids_128": []
    },
    {
        "id": 8,
        "timestamp": "2025-05-26 15:06:05.000000",
        "smac": "DE:AD:BE:EF:00:02",
        "dmac": "FF:FF:FF:FF:FF:FF",
        "rssi": -48,
        "distance": 2.2,
        "company_id": "0x004C",
        "manufacturer_data": "4C000215A495B7C5FF8A7D7F811DAB",
        "packet_hash": "beaconflood2",
        "uuids_16": ["0xfeed"],
        "uuids_32": [],
        "uuids_128": []
    },
    {
        "id": 9,
        "timestamp": "2025-05-26 15:07:00.000000",
        "smac": "BE:EF:FA:CE:CA:FE",
        "dmac": "FF:FF:FF:FF:FF:FF",
        "rssi": -60,
        "distance": 3.5,
        "company_id": "0x0006",
        "manufacturer_data": "01:02:03:04:05:06:07:08",
        "packet_hash": "impersonation1",
        "uuids_16": ["0x1234"],
        "uuids_32": [],
        "uuids_128": []
    },
    {
        "id": 10,
        "timestamp": "2025-05-26 15:07:30.000000",
        "smac": "AA:BB:CC:DD:EE:FF",  # Impersonated device
        "dmac": "FF:FF:FF:FF:FF:FF",
        "rssi": -55,
        "distance": 3.0,
        "company_id": "0x0006",
        "manufacturer_data": "01:02:03:04:05:06:07:08",
        "packet_hash": "impersonation1",
        "uuids_16": ["0x1234"],
        "uuids_32": [],
        "uuids_128": []
    },
    {
        "id": 11,
        "timestamp": "2025-05-26 15:08:00.000000",
        "smac": "FA:KE:MI:TM:00:01",
        "dmac": "FF:FF:FF:FF:FF:FF",
        "rssi": -38,
        "distance": 1.5,
        "company_id": "0x00FF",
        "manufacturer_data": "MITM attack - Fake Data",
        "packet_hash": "mitmhash1",
        "uuids_16": [],
        "uuids_32": ["0x9abc"],
        "uuids_128": []
    },
    {
        "id": 12,
        "timestamp": "2025-05-26 15:08:30.000000",
        "smac": "FA:KE:MI:TM:00:02",
        "dmac": "FF:FF:FF:FF:FF:FF",
        "rssi": -36,
        "distance": 1.2,
        "company_id": "0x00FF",
        "manufacturer_data": "MITM attack - Fake Data",
        "packet_hash": "mitmhash1",
        "uuids_16": [],
        "uuids_32": ["0x9abc"],
        "uuids_128": []
    },
    {
        "id": 13,
        "timestamp": "2025-05-26 15:09:00.000000",
        "smac": "66:77:88:99:AA:BB",
        "dmac": "FF:FF:FF:FF:FF:FF",
        "rssi": -42,
        "distance": 2.3,
        "company_id": "0xFFFF",
        "manufacturer_data": "Unknown vendor data",
        "packet_hash": "roguehash1",
        "uuids_16": [],
        "uuids_32": [],
        "uuids_128": ["550e8400-e29b-41d4-a716-446655440000"]
    },
    {
        "id": 14,
        "timestamp": "2025-05-26 15:09:30.000000",
        "smac": "77:88:99:AA:BB:CC",
        "dmac": "FF:FF:FF:FF:FF:FF",
        "rssi": -44,
        "distance": 2.6,
        "company_id": "0xFFFF",
        "manufacturer_data": "Unknown vendor data",
        "packet_hash": "roguehash1",
        "uuids_16": [],
        "uuids_32": [],
        "uuids_128": ["550e8400-e29b-41d4-a716-446655440000"]
    },
    {
        "id": 15,
        "timestamp": "2025-05-26 15:10:00.000000",
        "smac": "33:44:55:66:77:88",
        "dmac": "FF:FF:FF:FF:FF:FF",
        "rssi": -70,
        "distance": 5.0,
        "company_id": "0xABCD",
        "manufacturer_data": "Noise Data - Flood",
        "packet_hash": "floodhash1",
        "uuids_16": ["0xaaaa"],
        "uuids_32": [],
        "uuids_128": []
    }

]
    
    # Paketleri veritabanına ekle
    for packet in malicious_packets:
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO BLEPacket 
                (id, timestamp, smac, dmac, rssi, distance, company_id, manufacturer_data, packet_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                packet['id'], packet['timestamp'], packet['smac'], packet['dmac'],
                packet['rssi'], packet['distance'], packet['company_id'], 
                packet['manufacturer_data'], packet['packet_hash']
            ))
            print(f"✅ Paket {packet['id']} eklendi - {packet['smac']}")
                    # Insert UUIDs
            packet_id = packet['id']
            for uuid in packet.get('uuids_16', []):
                insert_uuids(cursor, conn, packet_id, packet.get('uuids_16', []), '16')
            for uuid in packet.get('uuids_32', []):
                insert_uuids(cursor, conn, packet_id, packet.get('uuids_32', []), '32')
            for uuid in packet.get('uuids_128', []):
                insert_uuids(cursor, conn, packet_id, packet.get('uuids_128', []), '128')

        except Exception as e:
            print(f"❌ Paket {packet['id']} eklenirken hata: {e}")
    
    conn.commit()
    
    # MAC Spoofing alert'leri ekle
    spoofing_alerts = [
        {
            'timestamp': '2025-05-05 18:38:45.510000',
            'uuid_type': 'manufacturer_data',
            'uuid': '0x0006',
            'company_id': '0x0006',
            'manufacturer_data': '01:09:21:0a:83:a0:ee:20:45:48:44:45:53:4b:54:4f:50:2d:45:48:33:33:54:31:35',
            'conflicting_macs': ['27:df:d0:83:01:3f', '69:84:17:7f:fd:d9', 'aa:bb:cc:dd:ee:ff']
        }
    ]
    
    for alert in spoofing_alerts:
        try:
            cursor.execute('''
                INSERT INTO MACSpoofingAlerts 
                (timestamp, uuid_type, uuid, company_id, manufacturer_data, conflicting_macs)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                alert['timestamp'], alert['uuid_type'], alert['uuid'], 
                alert['company_id'], alert['manufacturer_data'], 
                ', '.join(alert['conflicting_macs'])
            ))
            print(f"✅ MAC Spoofing alert eklendi")
        except Exception as e:
            print(f"❌ MAC Spoofing alert eklenirken hata: {e}")
    
    conn.commit()
    conn.close()
    
    print("🎯 Saldırı simülasyon verileri başarıyla eklendi!")
    print("📊 Eklenen veriler:")
    print("   • 10 adet malicious BLE paketi")
    print("   • 3 adet replay attack örneği")
    print("   • 4 adet MAC spoofing örneği")
    print("   • 1 adet MAC spoofing alert")

def verify_malicious_data(db_path):
    """
    Eklenen saldırı verilerini doğrula
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    print("\n🔍 Saldırı verilerini doğrulama...")
    
    # Replay attack kontrolü
    cursor.execute('''
        SELECT smac, packet_hash, COUNT(*) as repeat_count
        FROM BLEPacket 
        WHERE packet_hash IN ('replayhash1', 'replayhash2')
        GROUP BY smac, packet_hash
        HAVING COUNT(*) > 1
    ''')
    replay_results = cursor.fetchall()
    
    print(f"🔄 Replay Attack tespiti: {len(replay_results)} adet")
    for result in replay_results:
        print(f"   • MAC: {result[0]}, Hash: {result[1]}, Tekrar: {result[2]}x")
    
    # MAC Spoofing kontrolü
    cursor.execute('''
        SELECT manufacturer_data, COUNT(DISTINCT smac) as mac_count, 
               GROUP_CONCAT(DISTINCT smac) as macs
        FROM BLEPacket 
        WHERE manufacturer_data = '01:09:21:0a:83:a0:ee:20:45:48:44:45:53:4b:54:4f:50:2d:45:48:33:33:54:31:35'
        GROUP BY manufacturer_data
        HAVING COUNT(DISTINCT smac) > 1
    ''')
    spoofing_results = cursor.fetchall()
    
    print(f"🎭 MAC Spoofing tespiti: {len(spoofing_results)} adet")
    for result in spoofing_results:
        print(f"   • Manufacturer Data: {result[0][:50]}...")
        print(f"   • Farklı MAC sayısı: {result[1]}")
        print(f"   • MAC'ler: {result[2]}")
    
    # Şüpheli cihaz kontrolü
    cursor.execute('''
        SELECT smac, COUNT(*) as packet_count, 
               MIN(timestamp) as first_seen, MAX(timestamp) as last_seen
        FROM BLEPacket 
        WHERE smac IN ('11:22:33:44:55:66', 'AA:BB:CC:DD:EE:FF', 'aa:bb:cc:dd:ee:ff')
        GROUP BY smac
    ''')
    suspicious_results = cursor.fetchall()
    
    print(f"⚠️ Şüpheli cihazlar: {len(suspicious_results)} adet")
    for result in suspicious_results:
        print(f"   • MAC: {result[0]}, Paket: {result[1]}, İlk: {result[2]}, Son: {result[3]}")
    
    conn.close()

