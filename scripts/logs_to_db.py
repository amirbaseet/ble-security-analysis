import pyshark
import sqlite3
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from collections import defaultdict
from config import DB_PATH, PCAP_FILE
from utils.db_utils import init_db, insert_packet, insert_uuids, insert_spoof_alert
from utils.ble_utils import rssi_to_distance, generate_packet_hash



def process_ble_packets_optimized(pcap_file, conn, cursor):
    """Optimized BLE packet processing with batch operations and reduced DB calls"""
    
    capture = pyshark.FileCapture(
        pcap_file,
        display_filter='btle'
    )
    identity_map = defaultdict(set)
    
    # Batch containers
    packet_batch = []
    uuid_batch = []
    spoof_alerts = []
    
    batch_size = 1000  # Process in batches
    packet_count = 0
    
    # Pre-compile SQL statements for better performance
    insert_packet_sql = """
        INSERT INTO BLEPacket (timestamp, dmac, smac, rssi, distance, company_id, 
                              manufacturer_data, packet_hash) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """
    
    insert_uuid_sql = """
    INSERT INTO BLEPacketUUID (ble_packet_id, uuid_type, uuid) VALUES (?, ?, ?)
    """
    
    try:
        for pkt in capture:
            try:
                # Quick validation - skip early if no MAC addresses
                advertising_address = getattr(pkt.btle, 'advertising_address', None)
                scanning_address = getattr(pkt.btle, 'scanning_address', None)
                
                if not (advertising_address or scanning_address):
                    continue
                
                timestamp = pkt.sniff_time.strftime('%Y-%m-%d %H:%M:%S.%f')
                
                # Optimized MAC address extraction
                if scanning_address:
                    smac = scanning_address.lower()
                    dmac = advertising_address.lower() if advertising_address else 'ff:ff:ff:ff:ff:ff'
                else:
                    smac = advertising_address.lower()
                    dmac = 'ff:ff:ff:ff:ff:ff'
                
                # Optimized RSSI extraction
                rssi = None
                if hasattr(pkt, 'nordic_ble') and hasattr(pkt.nordic_ble, 'rssi'):
                    try:
                        rssi = int(pkt.nordic_ble.rssi)
                    except (ValueError, TypeError):
                        rssi = None
                
                distance = rssi_to_distance(rssi) if rssi is not None else None
                
                # Optimized UUID extraction with early capture
                uuid_data = {'16': set(), '32': set(), '128': set()}
                company_id = None
                manufacturer_data = None
                
                for layer in pkt.layers:
                    for field_name in layer.field_names:
                        try:
                            field_value = layer.get_field_value(field_name)
                            if not field_value:
                                continue

                            field_name_lower = field_name.lower()
                            if 'uuid_16' in field_name_lower:
                                uuid_str = str(field_value)
                                uuid_data['16'].add(uuid_str)
                                uuid_batch.append((len(packet_batch), '16', uuid_str))  # Capture UUID immediately
                            elif 'uuid_32' in field_name_lower:
                                uuid_str = str(field_value)
                                uuid_data['32'].add(uuid_str)
                                uuid_batch.append((len(packet_batch), '32', uuid_str))
                            elif 'uuid_128' in field_name_lower:
                                uuid_str = str(field_value)
                                uuid_data['128'].add(uuid_str)
                                uuid_batch.append((len(packet_batch), '128', uuid_str))
                            elif 'company_id' in field_name_lower:
                                company_id = str(field_value)
                            elif 'manufacturer_data' in field_name_lower or 'entry_data' in field_name_lower:
                                manufacturer_data = str(field_value)
                        except Exception as e:
                            print(f"Error processing field {field_name}: {e}")
                            continue

                if not any(uuid_data.values()):
                    # print(f"⚠️ Packet at {timestamp} has no UUIDs. Skipping.")
                    continue  # Skip packet if no UUIDs found

                # Generate hash efficiently
                hash_input = {
                    'timestamp': timestamp,
                    'dmac': dmac,
                    'uuids_16': ','.join(sorted(uuid_data['16'])),
                    'uuids_32': ','.join(sorted(uuid_data['32'])),
                    'uuids_128': ','.join(sorted(uuid_data['128'])),
                    'company_id': company_id or '',
                    'manufacturer_data': manufacturer_data or '',
                    'rssi': rssi or ''
                }
                print(f"Packet hash input: {hash_input}")
                packet_hash = generate_packet_hash(hash_input)
                
                # Add to batch
                packet_data = (
                    timestamp, dmac, smac, rssi, distance, 
                    company_id, manufacturer_data, packet_hash
                )
                packet_batch.append(packet_data)
                
                # Check for spoofing (optimized)
                all_uuids = []
                for uuid_type, uuid_set in uuid_data.items():
                    for uuid_val in uuid_set:
                        all_uuids.append((uuid_type, uuid_val, company_id, manufacturer_data))
                
                for uuid_key in all_uuids:
                    identity_map[uuid_key].add(dmac)
                    if len(identity_map[uuid_key]) > 1:
                        spoof_alerts.append({
                            'timestamp': timestamp,
                            'uuid_type': uuid_key[0],
                            'uuid': uuid_key[1],
                            'company_id': uuid_key[2],
                            'manufacturer_data': uuid_key[3],
                            'conflicting_macs': list(identity_map[uuid_key])
                        })
                
                packet_count += 1
                
                # Process batch when it reaches the limit
                if len(packet_batch) >= batch_size:
                    process_batch(cursor, conn, packet_batch, uuid_batch, spoof_alerts,
                                  insert_packet_sql, insert_uuid_sql)
                    packet_batch.clear()
                    uuid_batch.clear()
                    spoof_alerts.clear()
                    
                    if packet_count % 10000 == 0:
                        print(f"Processed {packet_count} packets...")

            except Exception as e:
                print(f"Error processing packet: {e}")
                continue
        
    finally:
        # Process remaining batch
        if packet_batch:
            process_batch(cursor, conn, packet_batch, uuid_batch, spoof_alerts,
                          insert_packet_sql, insert_uuid_sql)
        
        capture.close()
    
    return packet_count


def process_batch(cursor, conn, packet_batch, uuid_batch, spoof_alerts, 
                 insert_packet_sql, insert_uuid_sql):
    """Process a batch of packets efficiently"""
    
    try:
        # Batch insert packets
        cursor.executemany(insert_packet_sql, packet_batch)
        
        # Fetch last inserted row ID
        cursor.execute("SELECT last_insert_rowid()")
        last_row_id = cursor.fetchone()[0]
        
        start_packet_id = last_row_id - len(packet_batch) + 1
        
        # Prepare UUID batch with correct packet IDs
        uuid_batch_with_ids = []
        for packet_index, uuid_type, uuid_val in uuid_batch:
            actual_packet_id = start_packet_id + packet_index
            uuid_batch_with_ids.append((actual_packet_id, uuid_type, uuid_val))
            print(f"🗃️ Inserting UUID into BLEPacketUUID: packet_id={actual_packet_id}, type={uuid_type}, uuid={uuid_val}")
        
        # Batch insert UUIDs
        if uuid_batch_with_ids:
            cursor.executemany(insert_uuid_sql, uuid_batch_with_ids)
        
        # Insert spoof alerts
        for alert in spoof_alerts:
            insert_spoof_alert(cursor, conn, alert)
        
        # Commit the batch
        conn.commit()
        
    except Exception as e:
        print(f"Error processing batch: {e}")
        conn.rollback()


def process_ble_packets_ultra_fast(pcap_file, conn, cursor):
    """Ultra-fast version with minimal processing"""
    
    capture = pyshark.FileCapture(pcap_file)
    
    # Prepare bulk insert
    packets = []
    packet_count = 0
    
    # Disable autocommit for better performance
    conn.execute("BEGIN TRANSACTION")
    
    try:
        for pkt in capture:
            try:
                # Minimal validation
                if not hasattr(pkt, 'btle'):
                    continue
                
                advertising_address = getattr(pkt.btle, 'advertising_address', None)
                scanning_address = getattr(pkt.btle, 'scanning_address', None)
                
                if not (advertising_address or scanning_address):
                    continue
                
                # Fast extraction
                timestamp = pkt.sniff_time.strftime('%Y-%m-%d %H:%M:%S.%f')
                smac = (scanning_address or advertising_address).lower()
                dmac = (advertising_address or 'ff:ff:ff:ff:ff:ff').lower()
                
                # Quick RSSI
                rssi = None
                if hasattr(pkt, 'nordic_ble') and hasattr(pkt.nordic_ble, 'rssi'):
                    try:
                        rssi = int(pkt.nordic_ble.rssi)
                    except:
                        pass
                
                distance = rssi_to_distance(rssi) if rssi else None
                
                packets.append((timestamp, dmac, smac, rssi, distance, None, None, ''))
                packet_count += 1
                
                # Bulk insert every 5000 packets
                if len(packets) >= 5000:
                    cursor.executemany("""
                        INSERT INTO BLEPacket (timestamp, dmac, smac, rssi, distance, 
                                             company_id, manufacturer_data, packet_hash) 
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, packets)
                    packets.clear()
                    
                    if packet_count % 50000 == 0:
                        print(f"Ultra-fast processed {packet_count} packets...")
                        conn.commit()
                        conn.execute("BEGIN TRANSACTION")
            
            except:
                continue
    
    finally:
        # Insert remaining packets
        if packets:
            cursor.executemany("""
                INSERT INTO BLEPacket (timestamp, dmac, smac, rssi, distance, 
                                     company_id, manufacturer_data, packet_hash) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, packets)
        
        conn.commit()
        capture.close()
    
    return packet_count


if __name__ == "__main__":
    conn, cursor = init_db(DB_PATH)
    
    print("Processing BLE packets (optimized)...")
    
    # Choose processing method:
    # 1. Full featured but optimized
    packet_count = process_ble_packets_optimized(PCAP_FILE, conn, cursor)
    
    # 2. Ultra-fast minimal processing (uncomment to use)
    # packet_count = process_ble_packets_ultra_fast(PCAP_FILE, conn, cursor)
    
    conn.close()
    print(f"✅ {packet_count} BLE packets processed and saved.")
