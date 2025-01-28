#!/bin/bash

# Script eseguito all'avvio del container, gestisce sia lo sniffing che il suo post-processing

# Interfaccia di rete (eth0 dovrebbe andare bene, standard per il container)
INTERFACE="-i eth0"

# Possibili limiti (per test), abbastanza per mostrare la func "write_to_multiple_files()"
LIMITS="-c 1200"

# Regole di rotazione
ROTATE="-b filesize:1024"

# Percorsi e volumi
INPUT_DIR="/input"
OUTPUT_DIR="/output"
TSHARK_OUTPUT="$INPUT_DIR/capture.json" #raw_$(date +%Y%m%d_%H%M%S)"

# Parametri di avvio dello sniffing con wireshark
TSHARK_ARGS="$INTEFACE -T json $ROTATE $LIMITS -w $TSHARK_OUTPUT"

# Funzione per processare un file
process_file() {
    local file="$1"
    echo "Processing file: $file"
    python3 /app/json2udm.py "$file" $OUTPUT_DIR/"$file"
    if [[ $? -eq 0 ]]; then
        echo "Processing successful, removing file: $file"
        rm "$file" # Rimuovi il file solo se l'elaborazione è andata a buon fine
    else
        echo "Error processing file: $file. Keeping the original file."
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

# Verifica
if ! tshark $TSHARK_ARGS &; then
    echo "Failed to start tshark"
    exit 1
fi

# Gestione dei file già presenti nella directory
find "$INPUT_DIR" -name "raw*" -print0 | while IFS= read -r -d $'\0' file; do
    process_file "$file"
done

# Monitora la creazione di nuovi file
inotifywait -m -e create --format '%w%f' "$INPUT_DIR" | while read NEW_FILE; do
    if [[ "$NEW_FILE" == "$INPUT_DIR/$TSHARK_OUTPUT"* ]]; then
        process_file "$NEW_FILE"
    fi
done

# Monitora nuovi file completati in scrittura
inotifywait -m -e close_write --format "%w%f" "$capture_dir" | while read new_file; do
  echo "File completato: $new_file"
  # Esegui azioni sul file, ad esempio rinominalo o processalo
  timestamp=$(date +%Y%m%d_%H%M%S)
  mv "$new_file" "${new_file%_*}_$timestamp.pcap"
done

# Gestisce la terminazione di tshark (se necessario)
wait $TSHARK_PID
