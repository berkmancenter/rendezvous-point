# Rendezvous

**⚠️ Proof of Concept – Not for Production Use**

> This is a research prototype. It is **not audited** and **not ready for real-world whistleblowing**.

Rendezvous is a privacy-preserving protocol and prototype for whistleblowing that ensures disclosures are only released when a **safety threshold** is met – meaning enough people from the same organization have independently come forward. It provides anonymity, security, and accountability through:

- **IP-based organization verification**
- **Domain fronting to stay hidden**
- **Threshold-gated release via distributed crypto**
- **End-to-end encrypted to your recipient**

<img src="demo.gif" alt="demo"/>

## Protocol Architecture

### Roles

* **Whistleblower**: Submits sensitive information encrypted and split across servers.
* **Recipient**: Registered endpoint authorized to retrieve disclosures.
* **Rendezvous Point**: Independently operated server that holds encrypted disclosure shares and releases them when a threshold is met.

### Flow Overview

1. **Whistleblower**

   * Fetches a JWT credential from each rendezvous point via `GET /credential`.
   * Encrypts their disclosure using ephemeral Curve25519 + AES-GCM.
   * Splits the encrypted blob into secret shares using [Shamir Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing).
   * Submits one share to each rendezvous point using `POST /disclose`.

2. **Recipient**

   * Registers their public key with rendezvous points via `POST /register`.
   * Requests inbox authentication via `GET /inbox/:publicKey/challenge`.
   * Proves ownership of private key by encrypting challenge using ephemeral Curve25519 + AES-GCM.
   * Retrieves shares once the threshold is met with `GET /inbox/:publicKey`.
   * Reconstructs and decrypts the disclosure.
   * Optionally deletes the received share with `DELETE /inbox/:publicKey/:id`.

## Client Behavior

The demo [Swift client](ios) provides:

1. **Whistleblower**
   
   * Automatic credential retrieval across all rendezvous points
   * Encryption, secret sharing, and threshold submission of disclosures
   * Domain-fronted HTTPS via Google's fronting infrastructure
  
2. **Recipient**
   
   * Key generation and registration
   * Challenge-response inbox access
   * Decryption and automatic deletion of processed disclosures

## Server API

The demo [Go server](server) implements the following API, with in memory storage.

### `GET /credential`

Issues a JWT credential tied to the requestor’s IP and organization (via RDAP).

**Response:**

```json
{
  "organization": "Example Corp",
  "credential": "<jwt-signed-token>"
}
```

### `POST /disclose`

**Authenticated** with JWT credential.

**Body:**

```json
{
  "id": "UUID",
  "recipient": "<base64 Curve25519 public key>",
  "share": "<base64 secret share>"
}
```

### `POST /register`

Registers a recipient to receive disclosures.

**Body:**

```json
{
  "name": "Psst Legal Team",
  "publicKey": "<base64 Curve25519 public key>"
}
```

### `GET /recipients`

Returns a list of registered recipients.

**Body:**

```json
[
  {
    "name": "Psst Legal Team",
    "publicKey": "<base64 Curve25519 public key>"
  },
  ...
]
```

### `GET /inbox/:publicKey/challenge`

Requests a challenge token for a given public key initiate inbox authentication.

**Response:**

```json
{
  "token": "<base64 random challenge>",
  "serverPublicKey": "<base64 server key>"
}
```

### `GET /inbox/:publicKey`

**Authenticated** with AES-GCM `encryptedToken`.

Returns shares for any organization where a threshold has been met.

**Response:**

```json
[
  {
    "id": "UUID",
    "org": "Harvard University",
    "share": "<base64 secret share>"
  }
]
```

### `DELETE /inbox/:publicKey/:id`

**Authenticated** with AES-GCM `encryptedToken`.

Deletes a disclosure share by `id`.

## License

This project is released under the [MIT License](LICENSE).

## Contact

Maintained by [Nora Trapp](https://github.com/imperiopolis) and the Applied Social Media Lab at the Berkman Klein Center.
