from scapy.all import rdpcap
from datetime import datetime
import json
import sys
import time

# Maximum size for JSON file (1MB)
MAX_SIZE = 1024 * 1024

def mac_to_str(mac_bytes):
    """Converts a MAC address (bytes or string) into a readable string"""
    if isinstance(mac_bytes, str):
        return mac_bytes  # If it is already a string, return it directly
    return ':'.join(f'{b:02x}' for b in mac_bytes)

def ip_to_str(ip_bytes):
    """Converts an IP address (bytes) into a readable string"""
    return str(ip_bytes)

def format_time(timestamp):
    """Converts a UNIX timestamp into RFC 3339 format"""
    dt = datetime.fromtimestamp(float(timestamp))
    return dt.isoformat(timespec='seconds')  # RFC 3339 requires a precise format down to the seconds

def extract_pcap_data_with_scapy(pcap_file, output_json_file):
    start_time = time.time()  # Start measuring the execution time
    
    packets = rdpcap(pcap_file)  # Reads the packets from the pcap file
    extracted_data = []
    
    # number of processed packets
    packet_count = 0

    # We iterate through all the packets in the PCAP file  
    # For each packet, we extract details from the various layers and add them to the 'extracted_data' list
    for packet in packets:
        packet_count += 1  # Increments packets count
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

        # IPv6 level
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

        # The data from the packet, converted into a dictionary, is added to the list
        extracted_data.append(packet_info)

    # Convert the extracted data into a JSON string
    json_string = json.dumps(extracted_data, indent=4)

    # Calculate the JSON size
    size_in_bytes = len(json_string.encode('utf-8'))

    # Check if the size exceeds the allowed limit
    if size_in_bytes > MAX_SIZE:
        print(f"Errore: il file JSON supera il limite di dimensione consentito ({MAX_SIZE} bytes).")
        return

    # Save the extracted data in JSON format
    with open(output_json_file, 'w') as json_file:
        json_file.write(json_string)

    # Execution time
    execution_time = time.time() - start_time

    # Print the number of packets and the execution time
    print(f"File JSON creato: {output_json_file} (Dimensione: {size_in_bytes} bytes)")
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
