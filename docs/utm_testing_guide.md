# Manuale Operativo: Test Multi-Nodo su VM UTM (macOS Apple Silicon ARM64)

Questo manuale descrive la procedura passo-passo per configurare un ambiente di test di produzione simulato per **ZeroFeed** utilizzando **UTM Virtual Machines** su macOS Apple Silicon (M1/M2/M3/M4).

---

## 1. Architettura di Rete del Test

La topologia di test prevede l'isolamento del nodo Relay su una macchina virtuale Linux nativa (`linux/arm64`), simulando le condizioni reali di un server distribuito in cloud.

```mermaid
graph TD
    subgraph Host macOS (Apple Silicon ARM64)
        PUB["zerofeed publish<br/>(Publisher Client)<br/>IP: 192.168.64.1 (Host)"]
        SUB["zerofeed subscribe<br/>(Subscriber Client)<br/>IP: 192.168.64.1 (Host)"]
    end

    subgraph UTM Virtual Machine (Linux Ubuntu Server ARM64)
        RELAY["zerofeed relay<br/>(systemd Daemon)<br/>IP: 192.168.64.10:8443"]
        RL["RateLimiter & Memory Scrubber<br/>(Zero-Knowledge RAM Session)"]
        RELAY --- RL
    end

    PUB -->|"1. SPAKE2 PAKE Init (E2EE)"| RELAY
    SUB -->|"2. SPAKE2 PAKE Sub (E2EE)"| RELAY
    PUB ==>|"3. Encrypted Payload Stream (50KB/s)"| RELAY
    RELAY ==>|"4. Non-Blocking Fan-Out Forwarding"| SUB
```

### Componenti dell'Ambiente
1. **VM 1 (UTM Linux Relay)**: Server Ubuntu 22.04/24.04 ARM64 che esegue `zerofeed-linux-arm64` come demone `systemd` sulla porta TCP `8443`.
2. **Host Mac / VM 2 (Publisher)**: Client che trasmette flussi di dati cifrati in tempo reale tramite `zerofeed publish`.
3. **Host Mac / VM 3 (Subscriber)**: Client che riceve e decifra il flusso in tempo reale tramite `zerofeed subscribe`.

---

## 2. Passo 1: Cross-Compilazione dei Binari Multi-Architettura

Sul tuo Mac, compila i binari ottimizzati privi di dipendenze CGO eseguendo lo script automatizzato:

```bash
./scripts/build_release.sh
```

I binari verranno generati nella cartella `./bin/`:
- `zerofeed-linux-arm64` (per la VM UTM su Apple Silicon)
- `zerofeed-linux-amd64` (per VM x86_64 / Cloud)
- `zerofeed-darwin-arm64` (per il Mac Host)

---

## 3. Passo 2: Configurazione della Rete in UTM

 Per consentire la comunicazione TCP tra il Mac Host e la VM UTM (o tra più VM):

1. Apri **UTM** ed accedi alle **Impostazioni della VM Linux**.
2. Nella sezione **Network / Rete**:
   - Imposta **Mode / Modalità** su **Shared Network** (oppure **Bridged Advanced** se vuoi un IP reale sulla tua rete LAN).
3. Avvia la VM Linux e rileva l'indirizzo IP assegnato:
   ```bash
   ip a
   ```
   *(Esempio IP ottenuto: `192.168.64.10`)*

---

## 4. Passo 3: Trasferimento ed Installazione del Relay sulla VM Linux

### A. Trasferimento del Binario dal Mac alla VM
Dal terminale del Mac, invia il binario alla VM via `scp`:

```bash
scp ./bin/zerofeed-linux-arm64 user@192.168.64.10:/tmp/zerofeed-relay
```

### B. Installazione e Permessi sulla VM Linux
Collegati alla VM Linux tramite SSH:

```bash
ssh user@192.168.64.10
```

Esegui i comandi di installazione:

```bash
# Sposta il binario nel percorso di sistema
sudo mv /tmp/zerofeed-relay /usr/local/bin/zerofeed-relay
sudo chmod +x /usr/local/bin/zerofeed-relay

# Crea un utente di sistema dedicato senza privilegi di root
sudo useradd --system --no-create-home --shell /bin/false zerofeed
```

---

## 5. Passo 4: Configurazione del Demone systemd

Sulla VM Linux, crea il file di servizio `systemd`:

```bash
sudo nano /etc/systemd/system/zerofeed-relay.service
```

Incolla la seguente configurazione di produzione:

```ini
[Unit]
Description=ZeroFeed Zero-Knowledge Encrypted Relay Node
After=network.target
Wants=network.target

[Service]
Type=simple
User=zerofeed
Group=zerofeed
ExecStart=/usr/local/bin/zerofeed-relay relay --port 8443
Restart=always
RestartSec=3s
LimitNOFILE=65536

# Securing the systemd service (Hardening)
ProtectSystem=strict
ProtectHome=true
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

Ricarica `systemd` ed avvia il servizio:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now zerofeed-relay
```

Verifica lo stato del servizio sulla VM:

```bash
sudo systemctl status zerofeed-relay
```

---

## 6. Passo 5: Esecuzione dei Test di Esercizio Multi-Nodo

### Test A: Stream di Log in Tempo Reale tra Host e VM

1. **Avvia il Subscriber (sul Mac Host o su una seconda VM)**:
   ```bash
   ./bin/zerofeed-darwin-arm64 subscribe \
     --code "utm-live-test-passphrase-2026" \
     --relay "192.168.64.10:8443"
   ```

2. **Avvia il Publisher (sul Mac Host o un'altra terminale)**:
   Invia un flusso continuo di dati di log dal Mac verso la VM Linux:
   ```bash
   tail -f /var/log/system.log | ./bin/zerofeed-darwin-arm64 publish \
     --channel "utm-live-test-passphrase-2026" \
     --relay "192.168.64.10:8443"
   ```

3. **Esito Atteso**:
   I log di sistema del Mac appaiono istantaneamente sul terminale del Subscriber, cifrati end-to-end con SPAKE2 + AES-256-GCM. Il Relay sulla VM UTM instrada solo ciphertext cieco senza conoscere le chiavi.

---

### Test B: Stress Test & Verifica Ban IP per Pacchetti Malformati

Per verificare che la VM Linux droppi gli attacchi malformati e banni l'IP ostile:

1. Dalla VM o da un host di test, invia pacchetti TCP garbage verso la porta 8443 del Relay:
   ```bash
   nc -n 192.168.64.10 8443 < /dev/urandom
   ```

2. Ispeziona i log di sicurezza del Relay sulla VM:
   ```bash
   sudo journalctl -u zerofeed-relay -f
   ```

3. **Esito Atteso**:
   Dopo 3 pacchetti corrotti, il Relay sulla VM inserisce l'IP del mittente nella lista di ban ed interrompe immediatamente ogni successiva connessione TCP.

---

## 7. Scheda di Riferimento Rapido

| Comando | Descrizione |
| :--- | :--- |
| `./scripts/build_release.sh` | Compila i binari multi-architettura nella cartella `./bin/` |
| `sudo systemctl status zerofeed-relay` | Mostra lo stato del demone Relay sulla VM Linux |
| `sudo journalctl -u zerofeed-relay -n 50 -f` | Legge i log in tempo reale del Relay sulla VM |
| `sudo systemctl restart zerofeed-relay` | Riavvia il Relay pulendo tutte le sessioni RAM |
