# Project ZeroSign - Prototype for Ephemeral Compute Attestation (ECA/SAE)

This repository contains a prototype implementation of the **Ephemeral Compute Attestation (ECA)** protocol and its recommended transport, the **Static Artifact Exchange (SAE)**.

  * **ECA Protocol Draft:** [draft-ritz-eca-00](https://datatracker.ietf.org/doc/draft-ritz-eca-00/)
  * **ECA Implemention Guide:** [draft-ritz-eca-impl-00](https://datatracker.ietf.org/doc/draft-ritz-eca-00/)
  * **SAE Transport Draft:** [draft-ritz-sae-00](https://datatracker.ietf.org/doc/draft-ritz-sae-00)
  * **Formal Model:** [formal-model](https://github.com/eca-sae/internet-drafts-eca-sae/tree/pv0.3.0/formal-model)

**Note:** This is an experimental prototype intended to demonstrate the protocol flow and facilitate interoperability testing. It is a work-in-progress and is not suitable for production use.

-----

## Overview

This prototype demonstrates a complete, three-phase ECA ceremony. In this flow, an **Attester** (e.g., a container or VM) cryptographically proves its identity to a **Verifier** without any pre-provisioned operational credentials, a state referred to as the "privileged credential vacuum".

The exchange is performed over the **SAE transport**, where peers communicate asynchronously by publishing and polling for immutable artifacts in a shared repository. The security of the exchange relies on the cryptographic validity of the artifacts themselves, not on the transport.

The protocol's security properties have been analyzed using a **ProVerif model** to validate its resistance to network attackers under the assumption of a public Boot Factor.

-----

## Prerequisites

  * Docker Engine (20.10+) and Docker Compose
  * A Bash-compatible shell (4.0+) with `openssl`, `jq`, and `uuidgen`

-----

##  Quick Start

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/eca-sae/prototype-eca-sae.git
    cd prototype-eca-sae
    ```

2.  **Run a complete attestation ceremony:**

      * **Randomized Mode:** Executes a single, complete attestation with newly generated keys and factors.
        ```bash
        ./orchestrate.sh randomized
        ```
      * **Deterministic Mode:** Executes the ceremony using the pre-defined test vectors from the implementation guide. Useful for debugging and validation.
        ```bash
        ./orchestrate.sh deterministic --show-ar
        ```
      * **Parallel Mode:** Launches multiple concurrent attestation ceremonies to test for race conditions.
        ```bash
        ./orchestrate.sh randomized --parallel 3
        ```
-----

## How It Works

The prototype implementation is contained within `cli.py`, which orchestrates the three protocol phases. All cryptographic keys are derived deterministically from ceremony inputs using domain-separated HKDF-SHA-256.

-----

###  Protocol Flow

1.  **Phase 1: Authenticated Channel Setup**

      * The Attester proves possession of the **Boot Factor (BF)** and the secret **Instance Factor (IF)**.
      * It computes an **Integrity Hash Beacon** (`IHB = SHA-256(BF || IF)`) and publishes it along with an ephemeral X25519 public key. The payload is authenticated with an HMAC tag derived from a key based on `BF` and `IF`.

2.  **Phase 2: Validator Factor Release**

      * The Verifier validates the Phase 1 artifacts.
      * It then generates a secret **Validator Factor (VF)** and a fresh nonce.
      * The `VF` and nonce are encrypted to the Attester's public key using HPKE and the resulting ciphertext is signed.

3.  **Phase 3: Joint Possession Proof**

      * The Attester decrypts the `VF` and derives a final Ed25519 signing key from `BF` and `VF`.
      * It constructs a final **Entity Attestation Token (EAT)** containing proofs of joint possession (`JP = SHA-256(BF || VF)`) and a proof-of-possession (PoP) tag.
      * The EAT is signed and published. Upon successful validation, the Verifier issues a final, signed Attestation Result (AR).

-----

### Repository Structure

The `orchestrate.sh` script sets up a local environment simulating two repositories:

  * **Attester Repository:** An Nginx container serving the Attester's artifacts over HTTPS.
  * **Verifier Repository:** A local directory (`./s3-mock`) acting as a mock object store for the Verifier's artifacts.

-----

## Security Considerations

This prototype implements several security features specified in the drafts:

| Feature | Implementation Detail | Reference |
| :--- | :--- | :--- |
| **Replay Protection** | The Verifier maintains a persistent record of consumed `eca_uuid` values to enforce the "accept-once" rule. | `draft-ritz-eca-core.md` (Sec 3.1) |
| **Authentication** | All artifacts are authenticated using either HMAC-SHA-256 or Ed25519 signatures. | `draft-ritz-eca-core.md` (Sec 3.1) |
| **Freshness** | A Verifier-generated nonce is included in the final EAT to prevent replay within the ceremony. | `draft-ritz-eca-core.md` (Sec 4.1, Gate 8) |
| **Side-Channel Resistance** | Artifacts are padded to a fixed size to mitigate timing attacks. | `draft-ritz-sae.md` (Sec 5.1) |

-----

## Performance

The following metrics were observed during prototype testing on a consumer laptop.

| Metric | Value | Notes |
| :--- | :--- | :--- |
| **Protocol Execution Time** | \~1.3s | Time for pure protocol logic (Phases 1-3), excluding container startup. |
| **Full Attestation Time** | \~6s | Total time including container startup and network polling. |

-----


### Components
```
zerosign/
├── cli.py                  # Main protocol implementation
├── orchestrate.sh          # Docker orchestration
├── zerosign_work/lib/      # Cryptographic primitives
├── containers/             # Docker configurations
├── examples/               # Manifests and patterns
└── formal-model/           # ProVerif security proofs
```

-----


###  License

Apache 2.0

### Author

**Nathanael Ritz**  
Independent  
[nathanritz@gmail.com](mailto:nathanritz@gmail.com)
