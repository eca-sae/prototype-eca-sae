# Project ZeroSign - Prototype for Ephemeral Compute Attestation (ECA/SAE)

This repository contains a prototype implementation of the **Ephemeral Compute Attestation (ECA)** protocol and its recommended transport, the **Static Artifact Exchange (SAE)**.

  * **ECA Protocol Draft:** [draft-ritz-eca](https://datatracker.ietf.org/doc/draft-ritz-eca/)
  * **ECA Implemention Guide:** [draft-ritz-eca-impl](https://datatracker.ietf.org/doc/draft-ritz-eca/)
  * **SAE Transport Draft:** [draft-ritz-sae](https://datatracker.ietf.org/doc/draft-ritz-sae)
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

## Demonstration

For those who wish to see the protocol in action without running the prototype, the section below shows the log output from a complete, successful attestation ceremony. It demonstrates the three protocol phases, the asynchronous polling over the SAE transport, and the final validation gates being checked by the Verifier.

```bash
$ ./orchestrate.sh --show-ar
[ORCH] Launching 1 parallel attestation(s) in 'randomized' mode...
[RUN 1] STARTING (randomized): eca_uuid=29e9a005-3ba2-40bb-b845-21ddd4e0b082
...
attester-29e9a005  | [ATT] 0.00s - ATTESTER START
attester-29e9a005  | [ATT] 0.00s - PHASE 1: Authenticated Channel Setup
attester-29e9a005  | [ATT] 0.02s - PUBLISHED: /root/.wellknown/.../phase1_payload.cbor
attester-29e9a005  | [ATT] 0.02s - PUBLISHED: /root/.wellknown/.../initial.status
attester-29e9a005  | [ATT] 0.02s - PHASE 2: Waiting for Verifier Response
attester-29e9a005  | [ATT] 0.02s - POLLING for: https://mock-s3-sae-endpoint/.../vf.status
...
verifier-29e9a005  | [VER] 0.07s - FOUND: https://attester-29e9a005:8443/.../initial.status
verifier-29e9a005  | [VER] 0.15s - GATE 1: MAC verification
verifier-29e9a005  | [VER] 0.15s - GATE 4: KEM public key match
verifier-29e9a005  | [VER] 0.15s - PHASE 2: Generating Validator Factor
verifier-29e9a005  | [VER] 0.15s - PUBLISHED: /S3/zerosign-bucket/.../vf.status
...
attester-29e9a005  | [ATT] 1.27s - FOUND: https://mock-s3-sae-endpoint/.../vf.status
attester-29e9a005  | [ATT] 1.30s - PHASE 3: Final Evidence and Proof-of-Possession
attester-29e9a005  | [ATT] 1.30s - PUBLISHED: /root/.wellknown/.../evidence.status
attester-29e9a005  | [ATT] 1.30s - ATTESTER FINISHED.
...
verifier-29e9a005  | [VER] 1.25s - FOUND: https://attester-29e9a005:8443/.../evidence.status
verifier-29e9a005  | [VER] 1.29s - GATE 5: Evidence time window validation
verifier-29e9a005  | [VER] 1.29s - GATE 8: Nonce verification
verifier-29e9a005  | [VER] 1.29s - GATE 10: PoP (Proof of Possession) validation
verifier-29e9a005  | [VER] 1.29s - All gates passed. VERDICT: SUCCESS.
...
[ORCH] Decoding Attestation Results (--show-ar)…
--- DECODED ATTESTATION RESULT ---
{
  "-262148": "urn:ietf:params:rats:status:success",
  "1": "verifier-instance-001",
  "2": "38fb49847fd5004796ef95a94cc2b06e749923ada1325d648c90759cfcd03ff1",
  "6": 1759173340,
  "7": "29e9a005-3ba2-40bb-b845-21ddd4e0b082"
}
----------------------------------
```

For the complete, verbose log of this run, see [**`examples/example-run.md`**](https://github.com/eca-sae/prototype-eca-sae/blob/main/examples/example-run.md).


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

| Feature | Implementation Detail |
| :--- | :--- |
| **Replay Protection** | The Verifier maintains a persistent record of consumed `eca_uuid` values to enforce the "accept-once" rule. |
| **Authentication** | All artifacts are authenticated using either HMAC-SHA-256 or Ed25519 signatures. |
| **Freshness** | A Verifier-generated nonce is included in the final EAT to prevent replay within the ceremony. |
| **Side-Channel Resistance** | Artifacts are padded to a fixed size to mitigate timing attacks. |

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

Copyright 2025 Nathanael Ritz

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
