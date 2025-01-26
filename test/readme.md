# primo test

## primo test

capture1.json       è un file in output da Tshark, usato per fare sniffing in una semplice conversazione tra il mio portatile e fisso tramite netcat

_reale              è il risultato dell'esecuzione

_simulato           è il risultato atteso

lo scipt            è la prima versione che cerca i file nella cartella in cui si trova


## secondo test

_reale+output       è stato usato lo script nella root, subito dopo la prima introduzione dell'output

## terzo test

capture3.json       tshark -c 20 -e frame.time -e frame.number -e frame.protocols -e eth.src -e eth.dst -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -T json

capture4.json       tshark -i wlo1 -c 100 -T json

capture5.json       tshark -i wlo1 -c 25 -e frame.time_epoch -e frame.len -T json 

capture6.json       tshark -i wlo1 -c 25 -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -T json