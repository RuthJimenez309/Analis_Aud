# CloudGuard-LeakyBucket ☁️🛡️

**CloudGuard-LeakyBucket** is a lightweight, high-fidelity Cloud Security and IAM Posture simulation engine. It parses mock **AWS CloudTrail** logs in real-time to detect anomalous IAM behaviors, malicious threat infrastructure alignment, and potential S3 data exfiltration vectors.

This project represents **Day 2** of my Cybersecurity Portfolio, focusing on Cloud Infrastructure Security (CloudSec) and Identity & Access Management (IAM) analysis.

##  Core Features

- **IAM Privilege Escalation Detection:** Flags unauthorized `AccessDenied` attempts to overwrite critical S3 Bucket Policies (`PutBucketPolicy`).
- **Threat Intelligence Sync:** Automatically matches inbound log source IP addresses against a local threat feed database.
- **Data Exfiltration Rate-Limiting:** Implements a time-window evaluation tracker to detect automated data scraping actions (excessive `GetObject` calls).

##  Technical Stack

- **Language:** TypeScript
- **Runtime:** Node.js / ts-node
- **Log Source Archetype:** AWS CloudTrail (JSON Events)

##  Architecture & Data Flow

1. **Ingestion:** Streamed mock CloudTrail logs supply API call contexts (`userIdentity`, `eventName`, `sourceIpAddress`).
2. **Analysis Pipeline:** Sequential evaluation through three dedicated rule engines (IAM compliance, Threat Intelligence, and Rate Volatility).
3. **Alerting:** Real-time generation of security incident indicators accompanied by recommended mitigation playbooks.


##  Sample Security Alerts Output

```text
 [ALERTA IAM] Intento no autorizado de modificar políticas de S3!
   - Usuario: arn:aws:iam::123456789012:user/marketing-user
   - S3 Bucket: prod-customer-data

 [THREAT INTEL] Tráfico detectado desde IP maliciosa conocida: 198.51.100.12

 [CRÍTICO] ¡Detección de Exfiltración de Datos en S3!
   - Identidad comprometida (IAM): arn:aws:iam::123456789012:user/app-scrapper-key
   - Razón: 4 descargas en menos de un minuto.
```
