# Example run

The following is an example run of two parallel attestation procedures to demonstrate concurrency, latency and isolation.

$  ./scripts/orchestrate.sh --parallel 2 --show-ar

```bash
[... docker build preamble ...]

 ✔ Container mock-s3-sae-endpoint  Started                                                                                                                                                                    0.0s
[ORCH] Launching 2 parallel attestation(s) in 'randomized' mode...
[RUN 2] STARTING (randomized): eca_uuid=10db469d-c723-407c-88ff-48576a74b442
[RUN 1] STARTING (randomized): eca_uuid=29e9a005-3ba2-40bb-b845-21ddd4e0b082
[RUN 1] Launching containers in detached mode...
[RUN 2] Launching containers in detached mode...
[+] Running 1/0
 ✔ Container attester-29e9a005  Created                                                                                                                                                                       0.1s
 ⠋ Container verifier-29e9a005  Creating                                                                                                                                                                      0.0s
[+] Running 2/2
[+] Running 2/2tester-29e9a005  Started                                                                                                                                                                       0.1s
 ✔ Container attester-10db469d  Started                                                                                                                                                                       0.0s
 ✔ Container verifier-10db469d  Created                                                                                                                                                                       0.1s
attester-29e9a005  | [ATT-DIAG] My Hostname: 5cee92fa0b52, IP: 172.29.250.3
attester-29e9a005  | [ATT-DIAG] Configured to poll Verifier at: https://mock-s3-sae-endpoint/zerosign-bucket/29e9a005-3ba2-40bb-b845-21ddd4e0b082/
attester-29e9a005  | ---
attester-29e9a005  | [ATT] Web server started with PID 12.
attester-29e9a005  | [tools] https static on :8443 serving /root/.wellknown (self-signed)
[+] Running 2/205  | [VER-DIAG] My Hostname: efb0230adea1, IP: 172.29.250.5
 ✔ Container attester-10db469d  Started                                                                                                                                                                       0.0s
 ✔ Container verifier-10db469d  Started                                                                                                                                                                       0.1s
[RUN 2] Watching logs and waiting for result file...
attester-29e9a005  | [ATT] 0.00s - ATTESTER START
attester-29e9a005  | [ATT] 0.00s - PHASE 1: Authenticated Channel Setup
attester-29e9a005  | [ATT] 0.02s - PUBLISHED: /root/.wellknown/29e9a005-3ba2-40bb-b845-21ddd4e0b082/phase1_payload.cbor
attester-29e9a005  | [ATT] 0.02s - PUBLISHED: /root/.wellknown/29e9a005-3ba2-40bb-b845-21ddd4e0b082/phase1_mac.b64url
attester-29e9a005  | [ATT] 0.02s - PUBLISHED: /root/.wellknown/29e9a005-3ba2-40bb-b845-21ddd4e0b082/initial.status
attester-29e9a005  | [ATT] 0.02s - PHASE 2: Waiting for Verifier Response
attester-29e9a005  | [ATT] 0.02s - POLLING for: https://mock-s3-sae-endpoint/zerosign-bucket/29e9a005-3ba2-40bb-b845-21ddd4e0b082/vf.status (timeout: 20s)
attester-29e9a005  | [ATT] 0.11s - Polling https://mock-s3-sae-endpoint/zerosign-bucket/29e9a005-3ba2-40bb-b845-21ddd4e0b082/vf.status: Received status 404, will retry.
attester-10db469d  | [ATT-DIAG] My Hostname: 8c215a402345, IP: 172.29.250.4
attester-10db469d  | [ATT-DIAG] Configured to poll Verifier at: https://mock-s3-sae-endpoint/zerosign-bucket/10db469d-c723-407c-88ff-48576a74b442/
attester-10db469d  | ---
attester-10db469d  | [ATT] Web server started with PID 12.
attester-10db469d  | [tools] https static on :8443 serving /root/.wellknown (self-signed)
attester-10db469d  | [ATT] 0.00s - ATTESTER START
attester-10db469d  | [ATT] 0.00s - PHASE 1: Authenticated Channel Setup
attester-10db469d  | [ATT] 0.02s - PUBLISHED: /root/.wellknown/10db469d-c723-407c-88ff-48576a74b442/phase1_payload.cbor
attester-10db469d  | [ATT] 0.02s - PUBLISHED: /root/.wellknown/10db469d-c723-407c-88ff-48576a74b442/phase1_mac.b64url
attester-10db469d  | [ATT] 0.02s - PUBLISHED: /root/.wellknown/10db469d-c723-407c-88ff-48576a74b442/initial.status
attester-10db469d  | [ATT] 0.02s - PHASE 2: Waiting for Verifier Response
verifier-10db469d  | [VER-DIAG] My Hostname: 6942cf251e18, IP: 172.29.250.6
verifier-10db469d  | [VER-DIAG] Configured to poll Attester at: https://attester-10db469d:8443/10db469d-c723-407c-88ff-48576a74b442/
verifier-10db469d  | ---
attester-10db469d  | [ATT] 0.02s - POLLING for: https://mock-s3-sae-endpoint/zerosign-bucket/10db469d-c723-407c-88ff-48576a74b442/vf.status (timeout: 20s)
attester-10db469d  | [ATT] 0.11s - Polling https://mock-s3-sae-endpoint/zerosign-bucket/10db469d-c723-407c-88ff-48576a74b442/vf.status: Received status 404, will retry.
verifier-29e9a005  | [VER] 0.00s - VERIFIER START
verifier-10db469d  | [VER] 0.00s - VERIFIER START
verifier-10db469d  | [VER] 0.00s - POLLING for: https://attester-10db469d:8443/10db469d-c723-407c-88ff-48576a74b442/initial.status (timeout: 60s)
verifier-29e9a005  | [VER] 0.00s - POLLING for: https://attester-29e9a005:8443/29e9a005-3ba2-40bb-b845-21ddd4e0b082/initial.status (timeout: 60s)
verifier-29e9a005  | [VER] 0.07s - FOUND: https://attester-29e9a005:8443/29e9a005-3ba2-40bb-b845-21ddd4e0b082/initial.status
attester-10db469d  | 172.29.250.6 - - [29/Sep/2025 19:15:38] "HEAD /10db469d-c723-407c-88ff-48576a74b442/initial.status HTTP/1.1" 200 -
attester-29e9a005  | 172.29.250.5 - - [29/Sep/2025 19:15:38] "HEAD /29e9a005-3ba2-40bb-b845-21ddd4e0b082/initial.status HTTP/1.1" 200 -
verifier-10db469d  | [VER] 0.07s - FOUND: https://attester-10db469d:8443/10db469d-c723-407c-88ff-48576a74b442/initial.status
attester-10db469d  | 172.29.250.6 - - [29/Sep/2025 19:15:38] "GET /10db469d-c723-407c-88ff-48576a74b442/phase1_payload.cbor HTTP/1.1" 200 -
attester-29e9a005  | 172.29.250.5 - - [29/Sep/2025 19:15:38] "GET /29e9a005-3ba2-40bb-b845-21ddd4e0b082/phase1_payload.cbor HTTP/1.1" 200 -
attester-10db469d  | 172.29.250.6 - - [29/Sep/2025 19:15:39] "GET /10db469d-c723-407c-88ff-48576a74b442/phase1_mac.b64url HTTP/1.1" 200 -
verifier-10db469d  | [VER] 0.14s - GATE 1: MAC verification
attester-29e9a005  | 172.29.250.5 - - [29/Sep/2025 19:15:39] "GET /29e9a005-3ba2-40bb-b845-21ddd4e0b082/phase1_mac.b64url HTTP/1.1" 200 -
verifier-10db469d  | [VER] 0.15s - GATE 2: Instance authorization check
verifier-10db469d  | [VER] 0.15s - GATE 3: IHB validation
verifier-10db469d  | [VER] 0.15s - GATE 4: KEM public key match
verifier-29e9a005  | [VER] 0.15s - GATE 1: MAC verification
verifier-29e9a005  | [VER] 0.15s - GATE 2: Instance authorization check
verifier-29e9a005  | [VER] 0.15s - GATE 3: IHB validation
verifier-29e9a005  | [VER] 0.15s - GATE 4: KEM public key match
verifier-10db469d  | [VER] 0.15s - PHASE 2: Generating Validator Factor
verifier-29e9a005  | [VER] 0.15s - PHASE 2: Generating Validator Factor
verifier-29e9a005  | [VER] 0.15s - PUBLISHED: /S3/zerosign-bucket/29e9a005-3ba2-40bb-b845-21ddd4e0b082/verifier_proof.cose
verifier-29e9a005  | [VER] 0.15s - PUBLISHED: /S3/zerosign-bucket/29e9a005-3ba2-40bb-b845-21ddd4e0b082/vf.status
verifier-10db469d  | [VER] 0.15s - PUBLISHED: /S3/zerosign-bucket/10db469d-c723-407c-88ff-48576a74b442/verifier_proof.cose
verifier-29e9a005  | [VER] 0.15s - POLLING for: https://attester-29e9a005:8443/29e9a005-3ba2-40bb-b845-21ddd4e0b082/evidence.status (timeout: 60s)
verifier-10db469d  | [VER] 0.15s - PUBLISHED: /S3/zerosign-bucket/10db469d-c723-407c-88ff-48576a74b442/vf.status
verifier-10db469d  | [VER] 0.15s - POLLING for: https://attester-10db469d:8443/10db469d-c723-407c-88ff-48576a74b442/evidence.status (timeout: 60s)
attester-29e9a005  | 172.29.250.5 - - [29/Sep/2025 19:15:39] code 404, message File not found
attester-29e9a005  | 172.29.250.5 - - [29/Sep/2025 19:15:39] "HEAD /29e9a005-3ba2-40bb-b845-21ddd4e0b082/evidence.status HTTP/1.1" 404 -
verifier-29e9a005  | [VER] 0.18s - Polling https://attester-29e9a005:8443/29e9a005-3ba2-40bb-b845-21ddd4e0b082/evidence.status: Received status 404, will retry.
attester-10db469d  | 172.29.250.6 - - [29/Sep/2025 19:15:39] code 404, message File not found
attester-10db469d  | 172.29.250.6 - - [29/Sep/2025 19:15:39] "HEAD /10db469d-c723-407c-88ff-48576a74b442/evidence.status HTTP/1.1" 404 -
verifier-10db469d  | [VER] 0.18s - Polling https://attester-10db469d:8443/10db469d-c723-407c-88ff-48576a74b442/evidence.status: Received status 404, will retry.
attester-29e9a005  | [ATT] 1.27s - FOUND: https://mock-s3-sae-endpoint/zerosign-bucket/29e9a005-3ba2-40bb-b845-21ddd4e0b082/vf.status
attester-29e9a005  | [ATT] 1.29s - Fetched verifier_proof.cose successfully.
attester-29e9a005  | [ATT] 1.30s - PHASE 3: Final Evidence and Proof-of-Possession
attester-29e9a005  | [ATT] 1.30s - PUBLISHED: /root/.wellknown/29e9a005-3ba2-40bb-b845-21ddd4e0b082/evidence.cose
attester-29e9a005  | [ATT] 1.30s - PUBLISHED: /root/.wellknown/29e9a005-3ba2-40bb-b845-21ddd4e0b082/evidence.status
attester-29e9a005  | [ATT] 1.30s - ATTESTER FINISHED.
attester-10db469d  | [ATT] 1.31s - FOUND: https://mock-s3-sae-endpoint/zerosign-bucket/10db469d-c723-407c-88ff-48576a74b442/vf.status
attester-29e9a005  | [ATT] Attestation process finished. Waiting for shutdown signal...
attester-10db469d  | [ATT] 1.34s - Fetched verifier_proof.cose successfully.
attester-10db469d  | [ATT] 1.34s - PHASE 3: Final Evidence and Proof-of-Possession
attester-10db469d  | [ATT] 1.34s - PUBLISHED: /root/.wellknown/10db469d-c723-407c-88ff-48576a74b442/evidence.cose
attester-10db469d  | [ATT] 1.34s - PUBLISHED: /root/.wellknown/10db469d-c723-407c-88ff-48576a74b442/evidence.status
attester-10db469d  | [ATT] 1.34s - ATTESTER FINISHED.
attester-10db469d  | [ATT] Attestation process finished. Waiting for shutdown signal...
attester-29e9a005  | 172.29.250.5 - - [29/Sep/2025 19:15:40] "HEAD /29e9a005-3ba2-40bb-b845-21ddd4e0b082/evidence.status HTTP/1.1" 200 -
verifier-29e9a005  | [VER] 1.25s - FOUND: https://attester-29e9a005:8443/29e9a005-3ba2-40bb-b845-21ddd4e0b082/evidence.status
attester-10db469d  | 172.29.250.6 - - [29/Sep/2025 19:15:40] "HEAD /10db469d-c723-407c-88ff-48576a74b442/evidence.status HTTP/1.1" 200 -
verifier-10db469d  | [VER] 1.28s - FOUND: https://attester-10db469d:8443/10db469d-c723-407c-88ff-48576a74b442/evidence.status
attester-29e9a005  | 172.29.250.5 - - [29/Sep/2025 19:15:40] "GET /29e9a005-3ba2-40bb-b845-21ddd4e0b082/evidence.cose HTTP/1.1" 200 -
verifier-29e9a005  | [VER] 1.28s - GATE 5: Evidence time window validation
verifier-29e9a005  | [VER] 1.29s - GATE 7: Evidence signature verification
verifier-29e9a005  | [VER] 1.29s - GATE 6: Evidence schema compliance
verifier-29e9a005  | [VER] 1.29s - GATE 8: Nonce verification
verifier-29e9a005  | [VER] 1.29s - GATE 9: JP (Joint Possession) validation
verifier-29e9a005  | [VER] 1.29s - GATE 10: PoP (Proof of Possession) validation
verifier-29e9a005  | [VER] 1.29s - All gates passed. VERDICT: SUCCESS.
verifier-29e9a005  | [VER] 1.29s - PUBLISHED: /results/29e9a005-3ba2-40bb-b845-21ddd4e0b082/results.cose.b64url
verifier-29e9a005  | [VER] 1.29s - PUBLISHED: /results/29e9a005-3ba2-40bb-b845-21ddd4e0b082/results.status
attester-10db469d  | 172.29.250.6 - - [29/Sep/2025 19:15:40] "GET /10db469d-c723-407c-88ff-48576a74b442/evidence.cose HTTP/1.1" 200 -
verifier-10db469d  | [VER] 1.31s - GATE 5: Evidence time window validation
verifier-10db469d  | [VER] 1.31s - GATE 7: Evidence signature verification
verifier-10db469d  | [VER] 1.31s - GATE 6: Evidence schema compliance
verifier-10db469d  | [VER] 1.31s - GATE 8: Nonce verification
verifier-10db469d  | [VER] 1.31s - GATE 9: JP (Joint Possession) validation
verifier-10db469d  | [VER] 1.31s - GATE 10: PoP (Proof of Possession) validation
verifier-10db469d  | [VER] 1.31s - All gates passed. VERDICT: SUCCESS.
verifier-10db469d  | [VER] 1.31s - PUBLISHED: /results/10db469d-c723-407c-88ff-48576a74b442/results.cose.b64url
verifier-10db469d  | [VER] 1.31s - PUBLISHED: /results/10db469d-c723-407c-88ff-48576a74b442/results.status
verifier-29e9a005 exited with code 0
[RUN 1] Result file found.
verifier-10db469d exited with code 0
[RUN 2] Result file found.
[RUN 1] VERDICT: *PASSED* (6s)
[INFO] Signed AR (volume:zsn_attestation_results): /results/29e9a005-3ba2-40bb-b845-21ddd4e0b082/results.cose.b64url
[RUN 2] VERDICT: *PASSED* (6s)
[INFO] Signed AR (volume:zsn_attestation_results): /results/10db469d-c723-407c-88ff-48576a74b442/results.cose.b64url
[ORCH] Decoding Attestation Results (--show-ar)…
[ORCH] [AR] Verifying & decoding Attestation Result for 29e9a005-3ba2-40bb-b845-21ddd4e0b082…
[AR-DECODE] 1759173342.86s - Starting Attestation Result decoding...
[AR-DECODE] 1759173342.86s - Reading AR from: /results/29e9a005-3ba2-40bb-b845-21ddd4e0b082/results.cose.b64url
[AR-DECODE] 1759173342.87s - COSE signature VERIFIED.
--- DECODED ATTESTATION RESULT ---
{
  "-262148": "urn:ietf:params:rats:status:success",
  "1": "verifier-instance-001",
  "2": "38fb49847fd5004796ef95a94cc2b06e749923ada1325d648c90759cfcd03ff1",
  "4": 1759173640,
  "5": 1759173340,
  "6": 1759173340,
  "7": "29e9a005-3ba2-40bb-b845-21ddd4e0b082"
}
----------------------------------
[ORCH] [AR] Verifying & decoding Attestation Result for 10db469d-c723-407c-88ff-48576a74b442…
[AR-DECODE] 1759173343.50s - Starting Attestation Result decoding...
[AR-DECODE] 1759173343.50s - Reading AR from: /results/10db469d-c723-407c-88ff-48576a74b442/results.cose.b64url
[AR-DECODE] 1759173343.51s - COSE signature VERIFIED.
--- DECODED ATTESTATION RESULT ---
{
  "-262148": "urn:ietf:params:rats:status:success",
  "1": "verifier-instance-001",
  "2": "821571571e10b8675bea4a56c40afadce709eed645693dbcf16e5b708bff39c1",
  "4": 1759173640,
  "5": 1759173340,
  "6": 1759173340,
  "7": "10db469d-c723-407c-88ff-48576a74b442"
}
----------------------------------
[ORCH] All parallel runs complete.
```

**Interpretation:** From initial warm-up of containers and network init, the complete end to end flow completed in under 10s with the core protocol completing end-to-end in under 1.5s.
 