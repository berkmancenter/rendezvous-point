# Rendezvous

**⚠️ Proof of Concept – Not for Production Use**

Rendezvous is a privacy-preserving protocol and prototype for whistleblowing that ensures disclosures are only released when a **safety threshold** is met – meaning enough people from the same organization have independently come forward. It provides anonymity, security, and accountability through:

- **IP-based organization verification**
- **Domain fronting to stay hidden**
- **Threshold-gated release via distributed crypto**
- **End-to-end encrypted to your recipient**

<img src="demo.gif" alt="demo"/>

## Protocol Architecture

### Roles

* **Whistleblower**: Submits disclosures encrypted under recipient keys and verifiably split across servers.
* **Recipient**: Registered endpoint authorized to retrieve disclosures.
* **Rendezvous Point**: Independently operated server that holds encrypted disclosure shares and releases them when a threshold is met.

### Flow Overview

1. **Whistleblower**

   * Fetches a JWT credential from each rendezvous point via `GET /credential`.
   * Encrypts their disclosure using ephemeral Curve25519 + AES-GCM derived from the recipient's public key.
   * Splits the encrypted disclosure using [Shamir Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing).
   * For each share, computes a per-recipient commitment: `H(sharedKey || share || disclosureID)`
   * Submits one share, its commitment, and the ephemeral key to each rendezvous point using `POST /disclose`.

2. **Recipient**

   * Registers their public key with rendezvous points via `POST /register`.
   * Requests inbox authentication via `GET /inbox/:publicKey/challenge`.
   * Receives a random challenge + server ephemeral key.
   * Performs X25519 key agreement and returns the AES-GCM encrypted challenge.
   * Retrieves shares once the threshold is met with `GET /inbox/:publicKey`.
   * Verifies each share against its commitment using the ephemeral key and reconstructed shared secret, rejecting any unverifiable shares.
   * Reconstructs and decrypts the disclosure.
   * Optionally deletes the received share with `DELETE /inbox/:publicKey/:id`.

### Security Properties

The Rendezvous protocol provides the following properties under standard assumptions:

- **Forward Secrecy**: Each disclosure is encrypted with a new ephemeral key, so past disclosures remain secure even if the client key is compromised later.
- **Anonymity**: Whistleblowers use only ephemeral keys and never register or reuse long-lived identifiers. Domain fronting and minimal metadata further obscure origin.
- **Threshold Privacy**: No single server can reconstruct an encrypted disclosure or unilaterally determine an organization. Both disclosure recovery and IP-based organization verification require cooperation from a threshold of independent servers.
- **Verifiable Shares**: Each share is individually verifiable by the recipient using a keyed commitment, preventing forgery or tampering by malicious servers.
- **End-to-end Encryption**: Disclosures are encrypted directly to the recipient’s registered public key, and only the holder of the corresponding private key can decrypt them.

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
  "verifiableShare": {
    "ephemeralKey": "<base64 Curve25519 ephemeral public key>",
    "data": "<base64 secret share>",
    "commitment": "<base64 SHA256(sharedKey || share || id)>"
  }
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
  "publicKey": "<base64 server ephemeral key>",
  "nonce": "<base64 server random nonce>",
}
```

### `GET /inbox/:publicKey`

**Authenticated** with AES-GCM `encryptedToken` and `nonce`.

Returns shares for any organization where a threshold has been met.

**Response:**

```json
[
  {
    "id": "UUID",
    "org": "Harvard University",
    "verifiableShare": {
      "ephemeralKey": "<base64 Curve25519 ephemeral public key>",
      "data": "<base64 secret share>",
      "commitment": "<base64 SHA256(sharedKey || share || id)>"
    }
  }
]
```

### `DELETE /inbox/:publicKey/:id`

**Authenticated** with AES-GCM `encryptedToken` and `nonce`.

Deletes a disclosure share by `id`.

## License

This project is released under the [MIT License](LICENSE).

## Contact

Maintained by [Nora Trapp](https://github.com/imperiopolis) and the Applied Social Media Lab at the Berkman Klein Center.
