#!/bin/bash

# Script eseguito all'avvio del container, gestisce sia lo sniffing che il suo post-processing

# Parametri dello sniffing con wireshark
TSHARK_ARGS="-i eth0 -T json -b filesize:1024 -w $TSHARK_OUTPUT"

# Dichiarazione variabili
INPUT_DIR="/input"
OUTPUT_DIR="/output"
TSHARK_OUTPUT="$INPUT_DIR/raw_$(date +%Y%m%d_%H%M%S)"

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

# Gestisce la terminazione di tshark (se necessario)
wait $TSHARK_PID
