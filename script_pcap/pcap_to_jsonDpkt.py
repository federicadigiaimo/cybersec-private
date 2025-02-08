import dpkt
import json
import socket
import sys
from datetime import datetime, timezone
import time

# Maximum size for JSON file (1MB)
MAX_SIZE = 1024 * 1024

def mac_to_str(mac_bytes):
    """Converts a MAC address (bytes) into a readable string"""
    return ':'.join(f'{b:02x}' for b in mac_bytes)

def ip_to_str(ip_bytes):
    """Converts an IP address (bytes) into a readable string."""
    return socket.inet_ntoa(ip_bytes)

def format_time_rfc3339(timestamp):
    """Converts a UNIX timestamp into RFC 3339 format"""
    dt = datetime.fromtimestamp(timestamp, timezone.utc)
    return dt.isoformat(timespec='seconds')

# function to save the JSON file once the size limit is reached
def save_json_file(data, base_name, index):
    output_file = f"{base_name}_{index}.json"
    with open(output_file, 'w') as json_file:
        json.dump(data, json_file, indent=4, default=str)
    return output_file

def extract_pcap_with_dpkt(pcap_file, output_json_base):
    start_time = time.time()  # Inizio misurazione tempo di esecuzione

    # Open the pcap file and create a dpkt reader to parse the packets
    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        extracted_data = []
        current_size = 0
        file_index = 1
        packet_count = 0 # number of processed packets

        # We iterate through all the packets in the PCAP file  
        # For each packet, we extract details from the various layers and add them to the 'extracted_data' list
        for timestamp, buf in pcap:
            packet_count += 1 # Increments packets count
            packet_info = {
                "event": {
                    "type": "network_traffic",
                    "start_time": format_time_rfc3339(timestamp), # Capture time
                    "event_id": str(timestamp),
                    "device": "pcap_device"
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

            try:
                eth = dpkt.ethernet.Ethernet(buf)
                packet_info["source"]["mac"] = mac_to_str(eth.src)
                packet_info["destination"]["mac"] = mac_to_str(eth.dst)

                # Manage IPv4 packets
                if isinstance(eth.data, dpkt.ip.IP): # Livello IP (IPv4)
                    ip = eth.data
                    packet_info["network"]["protocol"] = "IPv4"
                    packet_info["source"]["ip"] = ip_to_str(ip.src)
                    packet_info["destination"]["ip"] = ip_to_str(ip.dst)

                    if isinstance(ip.data, dpkt.tcp.TCP): # TCP level
                        tcp = ip.data
                        packet_info["network"]["transport"] = "TCP"
                        packet_info["network"]["src_port"] = tcp.sport
                        packet_info["network"]["dst_port"] = tcp.dport

                    elif isinstance(ip.data, dpkt.udp.UDP): # UDP level
                        udp = ip.data
                        packet_info["network"]["transport"] = "UDP"
                        packet_info["network"]["src_port"] = udp.sport
                        packet_info["network"]["dst_port"] = udp.dport

                # Manage IPv6 packets
                elif isinstance(eth.data, dpkt.ip6.IP6):
                    ip6 = eth.data
                    packet_info["network"]["protocol"] = "IPv6"
                    packet_info["source"]["ip"] = socket.inet_ntop(socket.AF_INET6, ip6.src)
                    packet_info["destination"]["ip"] = socket.inet_ntop(socket.AF_INET6, ip6.dst)

                    if isinstance(ip6.data, dpkt.tcp.TCP):
                        tcp = ip6.data
                        packet_info["network"]["transport"] = "TCP"
                        packet_info["network"]["src_port"] = tcp.sport
                        packet_info["network"]["dst_port"] = tcp.dport

                    elif isinstance(ip6.data, dpkt.udp.UDP):
                        udp = ip6.data
                        packet_info["network"]["transport"] = "UDP"
                        packet_info["network"]["src_port"] = udp.sport
                        packet_info["network"]["dst_port"] = udp.dport

                event_json = json.dumps([packet_info], indent=4)
                event_size = len(event_json.encode("utf-8")) # Calculate the JSON event size

                # Check if the size exceeds the allowed limit
                if current_size + event_size > MAX_SIZE:
                    save_json_file(extracted_data, output_json_base, file_index) # Save the extracted data in JSON format in a file
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
            save_json_file(extracted_data, output_json_base, file_index)

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
    extract_pcap_with_dpkt(pcap_file, output_json)
