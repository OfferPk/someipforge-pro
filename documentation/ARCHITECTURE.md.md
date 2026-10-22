# SOMEIPForge Pro: Technical Architecture Specification

## 1\. System Overview

**SOMEIPForge Pro (v1.0.0)** is an enterprise automotive engineering suite and DevSecOps compliance platform for **AUTOSAR SOME/IP (Scalable service-Oriented MiddlewarE over IP)**, **SOME/IP-SD (Service Discovery)**, and **ISO 21434 / AUTOSAR SecOC** automotive cybersecurity.

Modern Software-Defined Vehicles (SDVs) and autonomous mobility architectures rely on Automotive Ethernet (100BASE-T1 / 1000BASE-T1) as their primary high-speed backbone. While diagnostic protocols such as ISO 13400-2 (DoIP) serve maintenance and flashing workflows, **SOME/IP is the foundational runtime communication middleware** interconnecting autonomous perception domains, central compute controllers, braking/steering actuators, and digital cockpits.

SOMEIPForge Pro provides standard-compliant wire-level synthesis, dissection, E2E CRC calculation, and automated ISO 21434 compliance auditing in a zero-dependency, self-contained architecture.

---

## 2\. AUTOSAR SOME/IP Protocol Specification

### 2.1 The 16-Byte Standard Header

Every SOME/IP frame begins with a mandatory 16-octet big-endian header:

 0                   1                   2                   3

 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|          Service ID           |      Method / Event ID        |  Message ID (32b)

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|                            Length                             |  Length (32b)

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|           Client ID           |          Session ID           |  Request ID (32b)

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

| Protocol Ver  | Interface Ver | Message Type  |  Return Code  |

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

|                       Payload / User Data ...                 |

\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

1. **Message ID (32 Bits)**:  
   - **Service ID (16 Bits)**: Identifies the service interface (e.g. `0x1000` for `VehicleBrakingService`).  
   - **Method / Event ID (16 Bits)**:  
     - Method ID: Bit 15 is `0` (`0x0001` \- `0x7FFF`).  
     - Event ID: Bit 15 is `1` (`0x8001` \- `0x8FFF` for events; `0x9001` \- `0x9FFF` for field notifiers).  
2. **Length (32 Bits, Big-Endian UInt32)**:  
   - Length of the message in octets starting from the Request ID (Byte 8\) through the end of the payload. Calculated as `8 + payload.length`.  
3. **Request ID (32 Bits)**:  
   - **Client ID (16 Bits)**: Uniquely identifies the calling client ECU or software component.  
   - **Session ID (16 Bits)**: Monotonically incrementing identifier to differentiate concurrent requests and detect replays.  
4. **Protocol Version (8 Bits)**:  
   - Standard value is `0x01` (or `0x02` in future revisions).  
5. **Interface Version (8 Bits)**:  
   - Major version of the service interface.  
6. **Message Type (8 Bits)**:  
   - `0x00`: `REQUEST` (expects a response)  
   - `0x01`: `REQUEST_NO_RETURN` (Fire and Forget)  
   - `0x02`: `NOTIFICATION` (Event publication / Field update)  
   - `0x80`: `RESPONSE` (Successful response to Request)  
   - `0x81`: `ERROR` (Error response to Request)  
   - `0x20` \- `0x24`: SOME/IP-TP (Transport Protocol) fragmented messages.  
7. **Return Code (8 Bits)**:  
   - `0x00`: `E_OK`  
   - `0x01`: `E_NOT_OK`  
   - `0x02`: `E_UNKNOWN_SERVICE`  
   - `0x03`: `E_UNKNOWN_METHOD`  
   - `0x06`: `E_TIMEOUT`  
   - `0x0C`: `E_E2E_WRONG_SEQUENCE`

---

## 3\. SOME/IP-SD (Service Discovery) Protocol

SOME/IP-SD dynamically locates services, negotiates instance bindings, and manages publish/subscribe eventgroups across the vehicle network.

- **Well-Known Header**:  
  - Service ID: `0xFFFF`  
  - Method ID: `0x8100`  
  - Client ID: `0x0000`  
  - Message Type: `0x02` (NOTIFICATION)  
  - Return Code: `0x00` (E\_OK)  
  - Multicast Address: `224.0.0.17`, UDP Port: `30490`  
- **SD Payload Structure**:  
  - `Flags` (8 Bits): Bit 7 \= Reboot Flag, Bit 6 \= Unicast Flag.  
  - `Reserved` (24 Bits): Three zero octets.  
  - `Length of Entries Array` (32 Bits) \+ Entries.  
  - `Length of Options Array` (32 Bits) \+ Options.  
- **Entry Types**:  
  - `0x00`: `FindService` (Locate an available service instance).  
  - `0x01`: `OfferService` (Announce availability with TTL \> 0\) / `StopOfferService` (TTL \= 0).  
  - `0x06`: `SubscribeEventgroup` / `StopSubscribeEventgroup`.  
  - `0x07`: `SubscribeEventgroupAck`.  
- **Options**:  
  - **IPv4 Endpoint Option (Type 0x04)**: Specifies the IP address, transport protocol (UDP/TCP), and L4 port number (`30501`) of the offered service.

---

## 4\. AUTOSAR End-to-End (E2E) & SecOC Protection

To satisfy safety standards (ISO 26262 ASIL-D) and cybersecurity requirements (ISO 21434 / UNECE WP.29 R155):

1. **AUTOSAR E2E Profiles**:  
   - **Profile 1**: Data ID (16-bit) \+ Alive Counter (4-bit nibble) \+ CRC-8 (SAE J1850 polynomial `0x1D`).  
   - **Profile 4 / 5**: Sequence Counter (16-bit) \+ CRC-16 (polynomial `0x1021`) or CRC-32 (polynomial `0x04C11DB7`).  
2. **AUTOSAR SecOC (Secure Onboard Communication)**:  
   - Safety-critical RPCs (such as steering angle or emergency brake requests) include a cryptographic Authenticator generated by a Hardware Security Module (HSM).  
   - Generates an AES-128-CMAC or HMAC-SHA256 truncated MAC (32 to 64 bits) coupled with a monotonic Freshness Value Manager (FVM) to defeat replay and tampering attacks.

---

## 5\. 10-Point ISO 21434 Zero-Trust Audit Rubric

| ID | Control Description | Reference Standard | Weight | Target Metric |
| :---- | :---- | :---- | :---- | :---- |
| **SOMEIP-SEC-01** | SOME/IP-SD Service Whitelisting | ISO 21434 Sec 9 / AUTOSAR AP | 12% | Static whitelist; drop rogue offers |
| **SOMEIP-SEC-02** | SOME/IP-SD Multicast Rate Limiting | ISO 21434 DoS Protection | 8% | Max \<= 20 pps on UDP 30490 |
| **SOMEIP-SEC-03** | SecOC Cryptographic Authentication | AUTOSAR SWS\_SecOC / R155 | 15% | AES-128-CMAC (\>= 32-bit MAC) |
| **SOMEIP-SEC-04** | E2E Protection & Sequence Checking | ISO 26262 ASIL-D / E2E Profile | 12% | Profile 1/4/11 CRC & Alive Counter |
| **SOMEIP-SEC-05** | VLAN Domain Segmentation | IEEE 802.1Q / ISO 21434 | 12% | IVI VLAN 200 \!= ADAS VLAN 300 |
| **SOMEIP-SEC-06** | Client ID & Method-Level IAM ACLs | NIST SP 800-207 Zero-Trust | 10% | Strict authorization matrix |
| **SOMEIP-SEC-07** | SOME/IP-TP Buffer Exhaustion Defense | AUTOSAR PRS\_SOMEIPTP | 8% | Fragment timeout \<= 1000ms |
| **SOMEIP-SEC-08** | Session ID Monotonic Anti-Replay | AUTOSAR PRS\_SOMEIP | 8% | Stateful monotonic session check |
| **SOMEIP-SEC-09** | Linux nftables Ingress Filtering | NIST SP 800-41 Gateway Defense | 8% | Drop unauthorized L4 endpoints |
| **SOMEIP-SEC-10** | Suricata Layer 7 Deep Packet Inspection | UNECE WP.29 R155 CSMS | 7% | L7 SOME/IP threat signatures |

---

## 6\. Software Architecture

product\_142/

├── README.md

├── build/

│   ├── someipforge-cli.py           \# Standalone DevSecOps CLI utility

│   └── someipforge-pro-v1.0.0.zip   \# Full release distribution archive

├── documentation/

│   ├── ARCHITECTURE.md              \# In-depth technical architecture

│   ├── USER\_GUIDE.md                \# Operational guide & CLI reference

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