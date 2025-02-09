# Parser pcap-jsonUDM

## Pyshark, Scapy e Dpkt
Per costruire un parser con input i file PCAP in Python esistono diverse librerie. In questo
caso si è deciso di considerare le tre principali per comprenderne vantaggi e svantaggi: Pyshark,
Scapy e Dpkt.

Pyshark è una libreria Python basata su tshark che permette di catturare e analizzare pacchetti
di rete sia da file PCAP che in tempo reale. Supporta diversi protocolli, consente di applicare
filtri per selezionare pacchetti specifici ed è compatibile con varie versioni di tshark.
Scapy è più potente e flessibile, permettendo non solo l’analisi, ma anche la creazione e manipolazione dei pacchetti, ideale per simulazioni di rete avanzate.
Dpkt, scritta in C, è la più veloce ed efficiente, adatta all'elaborazione di grandi volumi di traffico, ma con meno funzionalità avanzate.
Sia Scapy che Dpkt sono più semplici nelle loro capacità di parsing e manipolazione dei pacchetti.
Questa caratteristica, per`o, porta con sè un possibile svantaggio: potrebbero non essere in grado
di gestire alcune varianti di PCAP più complesse o non standard, che potrebbero essere state
create da versioni più recenti di Wireshark o con particolari configurazioni di cattura. Pyshark,
come già accennato, si basa su Tshark ed è più robusto e tollerante anche in caso di pacchetti
danneggiati.

# Scenari più adatti
La scelta della libreria più adatta dipende dal caso d’uso specifico. Pyshark è ideale quando
si ha bisogno di una soluzione semplice per l’analisi dei file PCAP senza necessità di manipolare
pacchetti. Scapy è la scelta migliore nel caso in cui si desidera maggiore controllo e flessibilità,
ideale per pentesting, fuzzing e testing dei protocolli di rete. Dpkt, infine, è la scelta giusta
quando le prestazioni e l’efficienza nell’elaborazione di grandi file PCAP sono una priorità.