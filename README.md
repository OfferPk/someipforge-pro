# SOMEIPForge Pro (v1.0.0)

> **AUTOSAR SOME/IP (Scalable service-Oriented MiddlewarE over IP) & SOME/IP-SD Automotive Ethernet Studio, 16-Byte Header & Service Discovery Engine, E2E Profile CRC Calculator, and ISO 21434 / SecOC Cybersecurity Auditor.**

---

## 🌟 Overview

**SOMEIPForge Pro** is a zero-dependency, standard-compliant automotive software suite designed for modern Software-Defined Vehicles (SDVs), Autonomous Driving (ADAS) domain controllers, and automotive Ethernet service-oriented architectures.

It delivers wire-level packet synthesis, live byte-stream dissection, SOME/IP-SD dynamic service discovery message generation, AUTOSAR E2E (End-to-End) CRC calculation, Linux automotive gateway firewall synthesis (`nftables`), Suricata Layer 7 intrusion detection signatures, and a 10-point Zero-Trust ISO 21434 / AUTOSAR SecOC compliance auditor.

---

## 🚀 Key Features

1. **AUTOSAR SOME/IP Standard-Compliant Engine**:  
   - Exact 16-byte mandatory big-endian header validation (Message ID, Length, Request ID, Protocol Version, Interface Version, Message Type, Return Code).  
   - Strict length field verification (`Length = 8 + payload.length`).  
   - Supports all standard message types: `REQUEST (0x00)`, `REQUEST_NO_RETURN (0x01)`, `NOTIFICATION (0x02)`, `RESPONSE (0x80)`, `ERROR (0x81)`, and SOME/IP-TP segments (`0x20`–`0x24`).  
2. **SOME/IP-SD (Service Discovery) Protocol Engine**:  
   - Encapsulates SD notifications under well-known Service ID `0xFFFF` and Method ID `0x8100`.  
   - Generates entries: `OfferService (0x01)`, `FindService (0x00)`, `SubscribeEventgroup (0x06)`, and confirmations.  
   - Encodes IPv4 Endpoint Options (Type `0x04`) declaring target IP addresses, transport protocol (UDP/TCP), and L4 ports (`30501`).  
3. **AUTOSAR End-to-End (E2E) & SecOC Protection**:  
   - Built-in E2E Profile 1 CRC-8 (SAE J1850 polynomial `0x1D`) and Profile 4 CRC-32 (polynomial `0xEDB88320`) calculators.  
   - Evaluates AUTOSAR SecOC cryptographic MAC authentication (AES-128-CMAC with Freshness Value Manager).  
4. **10-Point ISO 21434 & SecOC Cybersecurity Auditor**:  
   - Evaluates vehicle SOA security against rogue service offers, multicast broadcast flooding, E2E sequence gaps, IEEE 802.1Q VLAN domain isolation, and client authorization ACLs.  
   - Generates compliance scores (0–100), letter grades (A+ to F), and remediation roadmaps.  
5. **Automotive Gateway Rule Synthesizer**:  
   - Production-ready Linux `nftables` packet filtering scripts for automotive central gateways.  
   - Suricata Layer 7 intrusion detection signatures detecting header fuzzing, rogue SD offers, and deserialization errors.  
   - AUTOSAR Adaptive Platform ARXML service interface models.  
6. **Wireshark PCAP Generator**:  
   - Produces standard Libpcap 2.4 binary captures with synthetic Ethernet, IPv4, UDP, and SOME/IP / SOME/IP-SD frames for offline Wireshark inspection.  
7. **Dual Form Factor**:  
   - Interactive Dark Modern Automotive Web Studio (`source-code/index.html`).  
   - DevSecOps CLI (`build/someipforge-cli.py`) with strict CI/CD exit gating (`--strict`).

---

## 📂 Directory Layout

product\_142/

├── README.md

├── build/

│   ├── someipforge-cli.py           \# Standalone DevSecOps CLI utility

│   └── someipforge-pro-v1.0.0.zip   \# Full release distribution archive

├── documentation/

│   ├── ARCHITECTURE.md              \# In-depth technical architecture

│   ├── USER\_GUIDE.md                \# User manual & CLI reference

│   └── MONETIZATION\_AND\_MARKETING\_PLAYBOOK.md \# Commercial strategy & pricing

├── screenshots/

│   ├── someip-studio-preview.svg    \# Visual Web Studio preview

│   └── someip-architecture-diagram.svg \# Automotive SOA architecture diagram

└── source-code/

    ├── app.js                       \# Interactive Web Studio application controller

    ├── someip-config-synthesizer.js \# nftables & Suricata rule generator

    ├── someip-forge.css             \# High-contrast cockpit UI styling

    ├── someip-protocol-engine.js    \# Core encoder, decoder & PCAP engine

    ├── someip-security-auditor.js   \# 10-point ISO 21434 compliance auditor

    └── index.html                   \# Web Studio user interface

---

## ⚡ Quick Start

### 1\. Web Studio

Open `source-code/index.html` in any web browser.

### 2\. Standalone CLI

\# Make CLI executable

chmod \+x build/someipforge-cli.py

\# Synthesize a SOME/IP Method Request

python3 build/someipforge-cli.py build-packet \--service-id 0x1000 \--method-id 0x0001 \--payload-hex "01 FF 00 00"

\# Synthesize a SOME/IP-SD OfferService Announcement

python3 build/someipforge-cli.py build-packet \--sd-offer

\# Dissect raw SOME/IP hex bytes

python3 build/someipforge-cli.py dissect \--hex "10 00 00 01 00 00 00 10 00 42 00 01 01 01 00 00 01 FF 00 00 27 60 8C 94"

\# Calculate E2E Profile 4 CRC-32

python3 build/someipforge-cli.py calc-e2e \--data-hex "01 FF 00 00" \--profile profile4

\# Execute ISO 21434 Security Audit

python3 build/someipforge-cli.py audit

\# Generate Wireshark PCAP Capture

python3 build/someipforge-cli.py export-pcap \--out someip-capture.pcap

---

## 🧪 Automated Testing

Run the included comprehensive 10-vector test suite:

python3 test\_someipforge.py

Verification covers:

1. 16-byte header assembly and length field calculations.  
2. SOME/IP-SD OfferService frame construction and option parsing.  
3. AUTOSAR E2E Profile 1 CRC-8 polynomial calculation.  
4. AUTOSAR E2E Profile 4 CRC-32 polynomial calculation.  
5. Libpcap Wireshark capture generation and RFC 1071 IP checksums.  
6. Cross-runtime parity (Node.js and Python CLI byte-level match).  
7. ISO 21434 High-Security SDV audit (100% Score, Grade A+, COMPLIANT).  
8. ISO 21434 Insecure Legacy audit (0% Score, Grade F, NON\_COMPLIANT).  
9. Strict CI/CD exit code gating (`--strict` flag).  
10. Gateway rule synthesizer integrity (nftables and Suricata rule validation).