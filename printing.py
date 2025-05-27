import pyshark
from config import DB_PATH, PCAP_FILE

# Load the capture file with 'nordic_ble' filter (adjust as needed)
capture = pyshark.FileCapture(PCAP_FILE, display_filter='nordic_ble')

for index, packet in enumerate(capture):
    # Check if the packet has a 'nordic_ble' layer
    if hasattr(packet, 'nordic_ble'):
        layer = packet.nordic_ble
        print(f"\n--- Packet {index + 1} --- (nordic_ble Layer Only)")
        for field_name in layer.field_names:
            if 'uuid' in field_name.lower():  # Check for UUID fields
                field_value = layer.get_field_value(field_name)
                print(f"  {field_name}: {field_value}")

# Close the capture when done
capture.close()
