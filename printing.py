import pyshark
from config import DB_PATH, PCAP_FILE

# Replace this with your actual pcap file path
# Load the capture file
capture = pyshark.FileCapture(PCAP_FILE, display_filter='btle')  # Adjust the filter as needed

for index, packet in enumerate(capture):
    # print(f"\n--- Packet {index + 1} ---")
    
    for layer in packet.layers:
        print(f"Layer: {layer.layer_name}")
        for field_name in layer.field_names:
            if 'uuid' in field_name.lower():  # Case-insensitive check for 'uuid'
                field_value = layer.get_field_value(field_name)
                print(f"  {field_name}: {field_value}")

# Close the capture when done
capture.close()