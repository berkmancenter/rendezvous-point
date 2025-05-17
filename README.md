# Rendezvous (Prototype)

**⚠️ Proof of Concept – Not for Production Use**

Rendezvous is a privacy-preserving protocol and prototype for whistleblowing that ensures disclosures are only released when a **safety threshold** is met – meaning enough people from the same organization have independently come forward. It provides anonymity, security, and accountability through:

- **IP-based organization verification**
- **Domain fronting to stay hidden**
- **Threshold-gated release via distributed crypto**
- **End-to-end encrypted to your target**

> This is a research prototype. It is **not secure**, **not audited**, and **not intended for real-world whistleblowing**.

---

## Project Overview

This repo represents a **multi-component prototype** that demonstrates the viability of the Rendezvous protocol. It consists of:

- A Swift-based iOS client app for whistleblowers to obtain credentials and submit encrypted disclosures
- A Go-based rendezvous point server prototype that issues organizational credentials and stores threshold-gated, encrypted disclosure shares

---

## Key Concepts

- **Organization Credentialing:** The client obtains a signed credential proving they are on an organization's network using IP-based RDAP lookups.
- **Domain Fronting:** Used to tunnel communication covertly through trusted CDNs (e.g. Google) to avoid organizational surveillance.
- **Threshold-Gated Release:** Disclosures are split into shares and stored across rendezvous points. Only when a threshold of coworkers have submitted can the disclosure be reconstructed.
- **End-to-End Encryption:** Disclosures are encrypted using the recipient's public key and never accessible to any RP.

---

## iOS Client

Built in Swift, the iOS app handles:

- Credential acquisition via domain-fronted requests
- Disclosure construction and encryption
- Secret-sharing of disclosures to multiple RPs
- UI flows for whistleblower interaction

This is a proof-of-concept and does not persist credentials, keys, or received disclosures.

---

## Server

The Go prototype provides:

- IP-to-org credential issuance
- In-memory storage of secret shares
- Threshold-based routing of disclosure shares to the recipient
