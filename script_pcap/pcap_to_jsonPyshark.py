import pyshark
import json
import sys
import time
from datetime import timezone

# Maximum size for JSON file (1MB)
MAX_SIZE = 1024 * 1024

def extract_pcap_data(pcap_file, output_json_base):
    """
    Args:  
        pcap_file (str): Path to the PCAP file to be analyzed  
        output_json_file (str): Path to the JSON file to be created with the extracted data  

    Functionality:  
        Analyzes the PCAP file and converts the packet data into a structured JSON format  
        Saves the data into a JSON file, ensuring that the final size does not exceed the maximum limit of 1 MB  
    """
    start_time = time.time()
    cap = pyshark.FileCapture(pcap_file)
    
    extracted_data = [] # List to store the data extracted from the packets
    current_size = 0
    file_index = 1
    
    # number of processed packets
    packet_count = 0
      
    # function to save the JSON file once the size limit is reached
    def save_json_file(data, index):
        output_file = f"{output_json_base}_{index}.json"
        with open(output_file, 'w') as json_file:
            json.dump(data, json_file, indent=4, default=str)
        return 1

    # We iterate through all the packets in the PCAP file  
    # For each packet, we extract details from the various layers and add them to the 'extracted_data' list
    for packet in cap:
        try:
            packet_count += 1 # Increments packets count
            packet_info = {
                "event": {
                    "type": "network_traffic",
                 "start_time": packet.sniff_time.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S%z') if hasattr(packet, 'sniff_time') else None
                },
                "network": {
                    "protocol": None,
                    "transport": None,
                    "src_ip": None,
                    "dst_ip": None,
                    "src_port": None,
                    "dst_port": None
                },
                "source": {
                    "ip": None,
                    "mac": None
                },
                "destination": {
                    "ip": None,
                    "mac": None
                }
            }

            # Inspect the packet layers (eg. Ethernet, IP, TCP, UDP)
            # We use 'getattr' to safely retrieve values from the layers, returning None if the attribute is not present.
            if "ETH" in packet:  # Ethernet level
                eth_layer = packet.eth
                packet_info["source"]["mac"] = getattr(eth_layer, "src", None)
                packet_info["destination"]["mac"] = getattr(eth_layer, "dst", None)

            if "IP" in packet:   # IP level
                ip_layer = packet.ip
                packet_info["network"]["protocol"] = getattr(ip_layer, "version", None)
                packet_info["source"]["ip"] = getattr(ip_layer, "src", None)
                packet_info["destination"]["ip"] = getattr(ip_layer, "dst", None)

            if "TCP" in packet:  # TCP level
                tcp_layer = packet.tcp
                packet_info["network"]["transport"] = "TCP"
                packet_info["network"]["src_port"] = getattr(tcp_layer, "srcport", None)
                packet_info["network"]["dst_port"] = getattr(tcp_layer, "dstport", None)

            if "UDP" in packet:  # UDP level
                udp_layer = packet.udp
                packet_info["network"]["transport"] = "UDP"
                packet_info["network"]["src_port"] = getattr(udp_layer, "srcport", None)
                packet_info["network"]["dst_port"] = getattr(udp_layer, "dstport", None)

            event_json = json.dumps([packet_info], indent=4, default=str)
            event_size = len(event_json.encode("utf-8")) # Calculate the JSON event size

            # Check if the size exceeds the allowed limit
            if current_size + event_size > MAX_SIZE:
                save_json_file(extracted_data, file_index) # Save the extracted data in JSON format in a file
                file_index += 1
                extracted_data = []
                current_size = 0

            # The data from the packet, converted into a dictionary, is added to the list
            extracted_data.append(packet_info)
            current_size += event_size

        except Exception as e:
            print(f"Errore nell'elaborazione del pacchetto {packet_count}: {e}")

    # Saving the remaining packets
    if extracted_data:
        save_json_file(extracted_data, file_index)

    execution_time = time.time() - start_time
    print(f"Numero di pacchetti esaminati: {packet_count}")
    print(f"Tempo di esecuzione: {execution_time:.2f} secondi")

# Main execution block
if __name__ == "__main__":
    # Verify command line arguments
    if len(sys.argv) != 3:
        print("Usage: python pcap_to_Json.py <input_pcap_file> <output_json_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]   # Path to the input PCAP file
    output_json = sys.argv[2] # Path to the output JSON file

    # Call the main function with the provided arguments
    extract_pcap_data(pcap_file, output_json)
