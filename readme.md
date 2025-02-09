# Cybersecurity-projects-2024
Projects of the Cybersecurity course 2024/25, University of Bologna

# Project: Wireshark to Chronicle Pipeline

Questo progetto automatizza il processo di acquisizione dei pacchetti di rete tramite Wireshark (`tshark`), la loro conversione in formato JSON, e l'ulteriore trasformazione in un formato compatibile con Chronicle per l'analisi dei dati. Utilizza Docker per creare un ambiente isolato e gestire tutte le operazioni in modo efficiente.

## Authors
Studenti UNIBO della magistrale di Ingegneria Informatica

<img src="https://github.com/federicadigiaimo.png" width="40" height="40"> [Federica Di Giaimo](https://github.com/federicadigiaimo)

<img src="https://github.com/fillol.png" width="40" height="40"> [Filippo Lucchesi](https://github.com/fillol) 

<img src="https://github.com/Mariman1234.png" width="40" height="40"> [Mariano Mancini](https://github.com/Mariman1234) 

## Struttura del progetto

### Cartelle

- **`./sniff`**: Contiene i file pcap acquisiti da `tshark`.
- **`./processed`**: Archivia i file pcap che sono stati già processati, invece di eliminarli.
- **`./chronicle`**: Contiene i file JSON-UDM finali pronti per l'analisi con Chronicle.

### Docker e Docker Compose

Il deploy del progetto è realizzato tramite Docker, con un file `compose.yml` che definisce il servizio necessario per eseguire la pipeline.

- Il contenitore esegue `tshark` per catturare il traffico di rete.
- Dopo la cattura, i file pcap vengono convertiti in JSON, sfruttando uno script bash che implementa un listener di eventi.
- I file JSON vengono successivamente elaborati per essere trasformati in un formato adatto per Chronicle tramite uno script Python.

### Tecnologie

- **Wireshark**: Per catturare il traffico di rete.
- **Python**: Per la trasformazione dei file JSON in formato Chronicle.
- **Docker**: Per isolare l'ambiente e gestire le dipendenze.
- **inotify-tools**: Per monitorare le modifiche alla cartella di input e gestire la rotazione dei file.

## Come avviare il progetto

### 1. Clona il repository

```bash
git clone <URL_del_repository>
cd <nome_repository>
```

### 2. Costruisci l'immagine Docker

Esegui il comando `docker-compose` per costruire l'immagine:

```bash
docker-compose build
```

### 3. Avvia il contenitore

Una volta che l'immagine è stata costruita, avvia il contenitore con il comando:

```bash
docker-compose up -d
```

Questo avvierà `tshark`, che inizierà a catturare il traffico di rete. I file pcap verranno automaticamente processati e trasformati in JSON.

### 4. Monitoraggio e elaborazione

Il contenitore monitorerà la cartella `./sniff` per rilevare quando un file pcap è completo (usando `inotifywait`). Una volta che un file pcap è stato completamente scritto, verrà convertito in JSON e successivamente elaborato.

I file JSON processati saranno archiviati nella cartella `./chronicle`.

## Come funziona lo script `entrypoint.sh`

Lo script `entrypoint.sh` è il cuore del pipeline, gestendo l'acquisizione dei pacchetti e l'elaborazione:

1. **Avvio di `tshark`**: `tshark` viene eseguito in background per acquisire i pacchetti dalla rete (su `eth0` per default).
2. **Monitoraggio dei file**: Utilizza `inotifywait` per rilevare i file pcap che sono stati completati e scritti nella cartella `./sniff`.
3. **Elaborazione dei file**:
   - I file pcap vengono convertiti in JSON tramite `tshark`.
   - Il file JSON risultante viene trasformato ulteriormente utilizzando uno script Python per renderlo compatibile con Chronicle.
4. **Gestione degli errori**: In caso di errore nella conversione o nel processamento, il sistema segnala il problema e mantiene i file originali.

## Configurazione e personalizzazione

### Variabili di configurazione

L'interfaccia di rete dell'host su cui eseguire lo sniffing può essere configurate nel file `entrypoint.sh`:

_Viene comunque automaticamente cercata e configurata dal container in fase di avvio_

- **`INTERFACE`**: Interfaccia di rete da cui acquisire il traffico. (Default: `eth0`)

Le seguenti variabili possono essere configurate nel file `compose.yml`:

- **`LIMITS`**: Limiti per il numero di pacchetti da acquisire, utile per effettuare dimostrazioni e test. (Default: `-c 20000`)
- **`ROTATE`**: Opzioni di rotazione per la cattura dei file, determina ogni quanto avviene il post-processing. (Default: `-b filesize:10240`)

### Dipendenze

Il contenitore Docker include le seguenti dipendenze:

- `tshark` (Wireshark) per la cattura dei pacchetti di rete.
- `inotify-tools` per il monitoraggio delle modifiche ai file.
- `python` per l'elaborazione dei file JSON.
