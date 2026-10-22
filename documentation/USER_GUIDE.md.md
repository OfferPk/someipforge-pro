# SOMEIPForge Pro: User & Operational Guide

## 1\. Quickstart: Web Studio

SOMEIPForge Pro runs locally in any modern web browser without dependencies, external database connections, or installation steps.

### Launching the Web Studio

Open `source-code/index.html` directly in your browser:

\# On Linux / macOS:

open source-code/index.html

\# Or start a local static server:

python3 \-m http.server 8080 \--directory source-code

### Navigating the Studio

1. **Protocol Studio & Hex Inspector**:  
   - Set Service ID (`0x1000`), Method ID (`0x0001`), Client ID (`0x0042`), and Session ID (`0x0001`).  
   - Select Message Type (`0x00 REQUEST`, `0x80 RESPONSE`, `0x02 NOTIFICATION`).  
   - Input payload hex bytes (e.g. `01 FF 00 00`).  
   - Click **Append E2E Profile 4 CRC-32** to automatically compute and append the 4-byte CRC.  
   - Click **Synthesize SOME/IP Packet** to view the raw 24-byte wire frame and live dissection tree.  
   - Click **Export Wireshark PCAP** to download a `.pcap` capture file.  
2. **SOME/IP-SD Service Discovery**:  
   - Choose entry type (`OfferService`, `FindService`, `SubscribeEventgroup`).  
   - Configure TTL, Instance ID, and IPv4 endpoint (e.g. `192.168.1.20` on UDP `30501`).  
   - Click **Synthesize SD Packet** to preview the full multicast frame.  
3. **ISO 21434 & SecOC Cybersecurity Auditor**:  
   - Configure target security controls (SD Whitelisting, SecOC MAC algorithm, E2E profile, VLAN isolation, IAM method ACLs).  
   - Click **Re-run Security Audit** to compute the real-time score (0–100), letter grade (A+ to F), and remediation roadmap.  
   - Use the **Load High-Security SDV** (Grade A+) or **Load Insecure Legacy** (Grade F) buttons for instant benchmarking.  
4. **Gateway Firewall & ARXML**:  
   - Copy auto-generated Linux `nftables` ingress filtering scripts and Suricata Layer 7 SOME/IP threat signatures.  
5. **Automotive SOA Lifecycle Simulator**:  
   - Execute interactive visual timeline simulations:  
     - **Simulate Service Discovery & RPC**: Demonstrates dynamic SD negotiation followed by method execution.  
     - **Simulate E2E Event Stream**: Shows monotonic sequence increments and CRC verification.  
     - **Simulate Rogue Service Offer Attack**: Demonstrates firewall drop and IDS alerting when untrusted nodes attempt to advertise fake braking services.

---

## 2\. Command-Line Interface (CLI) Manual

The standalone Python CLI is located at `build/someipforge-cli.py`. It requires Python 3.8+ with standard libraries only.

### 2.1 Synthesizing SOME/IP Packets (`build-packet`)

\# Synthesize a standard SOME/IP Method Request

python3 build/someipforge-cli.py build-packet \--service-id 0x1000 \--method-id 0x0001 \--client-id 0x0042 \--session-id 0x0001 \--payload-hex "01 FF 00 00"

\# Synthesize a SOME/IP-SD OfferService Announcement (Multicast 224.0.0.17)

python3 build/someipforge-cli.py build-packet \--sd-offer

\# Save raw binary frame to disk

python3 build/someipforge-cli.py build-packet \--service-id 0x1000 \--method-id 0x0001 \--out request.bin

### 2.2 Dissecting Raw SOME/IP Packets (`dissect`)

\# Dissect a raw hex string

python3 build/someipforge-cli.py dissect \--hex "10 00 00 01 00 00 00 10 00 42 00 01 01 01 00 00 01 FF 00 00 27 60 8C 94"

\# Dissect a captured binary frame

python3 build/someipforge-cli.py dissect \--file request.bin

Output:

{

  "valid": true,

  "header": {

    "service\_id": "0x1000",

    "method\_or\_event\_id": "0x1",

    "is\_event": false,

    "length\_field": 16,

    "client\_id": "0x42",

    "session\_id": "0x1",

    "protocol\_version": 1,

    "interface\_version": 1,

    "message\_type": "REQUEST",

    "return\_code": "E\_OK"

  },

  "is\_service\_discovery": false,

  "payload\_hex": "01 FF 00 00 27 60 8C 94",

  "raw\_hex": "10 00 00 01 00 00 00 10 00 42 00 01 01 01 00 00 01 FF 00 00 27 60 8C 94"

}

### 2.3 Calculating AUTOSAR E2E Checksums (`calc-e2e`)

\# Calculate E2E Profile 4 CRC-32

python3 build/someipforge-cli.py calc-e2e \--data-hex "01 FF 00 00" \--profile profile4

\# Calculate E2E Profile 1 CRC-8 with Data ID 0x1000

python3 build/someipforge-cli.py calc-e2e \--data-hex "01 FF 00 00" \--profile profile1 \--data-id 0x1000

### 2.4 Executing ISO 21434 / SecOC Security Audits (`audit`)

\# Audit the default secure Software-Defined Vehicle profile

python3 build/someipforge-cli.py audit

\# Audit a custom profile with strict CI/CD exit gating

python3 build/someipforge-cli.py audit \--profile custom-profile.json \--strict

If the audit fails compliance criteria (score \< 85% or critical vulnerabilities present), `--strict` returns an exit code of `1`, halting automated build or OTA release pipelines.

### 2.5 Generating Wireshark PCAPs (`export-pcap`)

\# Export standard SOME/IP method capture

python3 build/someipforge-cli.py export-pcap \--out someip-capture.pcap

\# Export SOME/IP-SD multicast capture

python3 build/someipforge-cli.py export-pcap \--out someip-sd-capture.pcap \--sd

---

## 3\. Wireshark Capture Analysis

Generated PCAP captures conform to standard Libpcap 2.4 format:

1. Open `someip-capture.pcap` in Wireshark (v3.2+ includes native SOME/IP and SOME/IP-SD dissectors).  
2. Apply display filter `someip` or `someip_sd`.  
3. Wireshark parses:  
   - Message ID: `0x10000001` (Service 0x1000, Method 0x0001)  
   - Length: `16`  
   - Request ID: `0x00420001` (Client 0x0042, Session 0x0001)  
   - Message Type: `REQUEST (0x00)`  
   - Return Code: `E_OK (0x00)`