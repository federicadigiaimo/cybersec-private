#!/bin/bash

# Script eseguito all'avvio del container, gestisce sia lo sniffing che il suo post-processing

# Interfaccia di rete (eth0 dovrebbe andare bene, standard per il container)
INTERFACE="-i eth0"

# Possibili limiti (per test), abbastanza per mostrare la func "write_to_multiple_files()"
LIMITS="-c 2000"

# Regole di rotazione
ROTATE="-b filesize:1024"

# Percorsi e volumi
INPUT_DIR="/app/input"      # qui vengono messe le catture
TRASH_DIR="/app/trash"      # una volta tradotti in json, i pcap vanno qui
MID_DIR="/app/jsonized"     # i json pronti per parsing UDM
OUTPUT_DIR="/app/output"    # file pronti per chronicle

# Parametri di avvio dello sniffing con wireshark
TSHARK_ARGS="$INTERFACE $ROTATE $LIMITS -w $INPUT_DIR/capture.pcap"

# Funzione per processare un file
process_file() {
    local FILE="$(basename "$1" .pcap)"

    # Fase 1: pcap -> json (sposto il file in trash se andato a buon fine)
    tshark -r "$1" -T json > "$MID_DIR/$FILE.json" && mv "$1" $TRASH_DIR/
  
    # Fase 2: json -> UDM (sposto il file in output se andato a buon fine)
    python3 /app/json2udm.py "$MID_DIR/$FILE.json" "$OUTPUT_DIR/$FILE.json"

    if [[ $? -eq 0 ]]; then
        echo "Processing successful, removing file: "$MID_DIR/$FILE.json""
        rm "$MID_DIR/$FILE.json" # Rimuovi il file solo se l'elaborazione è andata a buon fine
    else
        echo "Error processing file: "$MID_DIR/$FILE.json". Keeping the original file."
    fi
}

# Gestione dell'errore nel caso di terminazione prematura di tshark
trap 'echo "Terminating tshark due to script exit"; kill $TSHARK_PID' EXIT

# Avvia tshark in background
echo "Starting tshark..."
tshark $TSHARK_ARGS &
TSHARK_PID=$!

# Log conferma
echo "Starting tshark with args: $TSHARK_ARGS"

# Monitora nuovi file completati in scrittura
inotifywait -m -e close_write --format "%w%f" "$INPUT_DIR" | while read NEW_FILE; do
  echo "File completato: $NEW_FILE"
  process_file "$NEW_FILE"
done

# Gestisce la terminazione di tshark (se necessario)
wait $TSHARK_PID
