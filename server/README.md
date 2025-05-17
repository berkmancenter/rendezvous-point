This is a minimal Go-based prototype for the Rendezvous protocol. It receives encrypted disclosures from clients and only forwards them to recipients (e.g. journalists or legal teams) once a **threshold** is met – i.e. enough users from the same organization have come forward.

## Functionality

- Receives end-to-end encrypted disclosures
- Verifies workplace affiliation via hashed credentials
- Tracks submissions in memory by organization
- Releases disclosures when threshold met

> ⚠️ This is a **proof-of-concept only**. It should **not** be used in production.
