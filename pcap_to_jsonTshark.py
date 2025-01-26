import subprocess
import sys

def extract_pcap_with_tshark(pcap_file, output_json_file):
    """
    Qui tshark ovviamente non offre il file json in formato UDM, si potrebbe integrare magari con lo script json -> UDM
    """
    # Esegue tshark e ottiene l'output JSON
    tshark_command = [
        "tshark", "-r", pcap_file, "-T", "json"
    ]
    result = subprocess.run(tshark_command, capture_output=True, text=True)

    if result.returncode != 0:
        print("Errore durante l'esecuzione di tshark:", result.stderr)
        return

    # Salva l'output JSON in un file
    with open(output_json_file, 'w') as json_file:
        json_file.write(result.stdout)

    print(f"File JSON creato: {output_json_file}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python pcap_to_Json.py <input_pcap_file> <output_json_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    output_json = sys.argv[2]

    # Chiama la funzione principale con gli argomenti forniti
    extract_pcap_with_tshark(pcap_file, output_json)
