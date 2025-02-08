from scapy.all import rdpcap, Scapy_Exception
from datetime import datetime
import json
import sys
import time

# Maximum size for JSON file (1MB)
MAX_SIZE = 1024 * 1024

def mac_to_str(mac_bytes):
    """Converts a MAC address (bytes or string) into a readable string"""
    if isinstance(mac_bytes, str):
        return mac_bytes    # If it is already a string, return it directly
    return ':'.join(f'{b:02x}' for b in mac_bytes)

def format_time(timestamp):
    """Converts a UNIX timestamp into RFC 3339 format"""
    dt = datetime.fromtimestamp(float(timestamp))
    return dt.isoformat(timespec='seconds') # RFC 3339 requires a precise format down to the seconds

# function to save the JSON file once the size limit is reached
def save_json_file(data, base_name, index):
    output_file = f"{base_name}_{index}.json"
    with open(output_file, 'w') as json_file:
        json.dump(data, json_file, indent=4)
    return output_file

def extract_pcap_data_with_scapy(pcap_file, output_json_base):
    start_time = time.time()
    
    packets = rdpcap(pcap_file) # Reads the packets from the pcap file
    
    extracted_data = [] # List to store the data extracted from the packets
    current_size = 0
    file_index = 1
    
    # number of processed packets
    packet_count = 0

    # We iterate through all the packets in the PCAP file  
    # For each packet, we extract details from the various layers and add them to the 'extracted_data' list
    for packet in packets:
        try:
            packet_count += 1   # Increments packets count
            packet_info = {
                "event": {
                    "type": "network_traffic",
                    "start_time": format_time(packet.time)  # Capture time
                },
                "network": {
                    "protocol": "Unknown",
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

            # Ethernet level
            if packet.haslayer("Ethernet"):
                eth = packet.getlayer("Ethernet")
                packet_info["source"]["mac"] = mac_to_str(eth.src)
                packet_info["destination"]["mac"] = mac_to_str(eth.dst)

            # IP level (IPv4)
            if packet.haslayer("IP"):
                ip = packet.getlayer("IP")
                packet_info["network"]["protocol"] = "IPv4"
                packet_info["source"]["ip"] = ip.src
                packet_info["destination"]["ip"] = ip.dst
                
            # IP level (IPv4)
            elif packet.haslayer("IPv6"):
                ipv6 = packet.getlayer("IPv6")
                packet_info["network"]["protocol"] = "IPv6"
                packet_info["source"]["ip"] = str(ipv6.src)
                packet_info["destination"]["ip"] = str(ipv6.dst)

            # TCP level
            if packet.haslayer("TCP"):
                tcp = packet.getlayer("TCP")
                packet_info["network"]["transport"] = "TCP"
                packet_info["network"]["src_port"] = tcp.sport
                packet_info["network"]["dst_port"] = tcp.dport

            # UDP level
            if packet.haslayer("UDP"):
                udp = packet.getlayer("UDP")
                packet_info["network"]["transport"] = "UDP"
                packet_info["network"]["src_port"] = udp.sport
                packet_info["network"]["dst_port"] = udp.dport

            event_json = json.dumps([packet_info], indent=4)
            event_size = len(event_json.encode("utf-8"))    # Calculate the JSON event size

            # Check if the size exceeds the allowed limit
            if current_size + event_size > MAX_SIZE:
                save_json_file(extracted_data, output_json_base, file_index)
                file_index += 1
                extracted_data = []
                current_size = 0

            extracted_data.append(packet_info)
            current_size += event_size

        except Exception as e:
            print(f"Errore nell'elaborazione del pacchetto {packet_count}: {e}")

    # Saving the remaining packets
    if extracted_data:
        save_json_file(extracted_data, output_json_base, file_index)

    execution_time = time.time() - start_time
    print(f"Numero di pacchetti esaminati: {packet_count}")
    print(f"Tempo di esecuzione: {execution_time:.2f} secondi")

# Main execution block
if __name__ == "__main__":
    # Verify command line arguments
    if len(sys.argv) != 3:
        print("Usage: python pcap_json.py <input_pcap_file> <output_json_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]   # Path to the input PCAP file
    output_json = sys.argv[2] # Path to the output JSON file

    # Call the main function with the provided arguments
    extract_pcap_data_with_scapy(pcap_file, output_json)