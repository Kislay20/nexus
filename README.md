# 🛡️ Nexus: Zero-Trust Agentic Commerce

**Nexus** is a Zero-Trust gateway designed for the era of AI-driven autonomous commerce. It securely bridges the gap between autonomous AI agents and actual financial settlement by enforcing a cryptographically verifiable, biometric-first approval loop for high-value transactions.

Built for the **PayPal AI Hackathon**, Nexus ensures that while AI agents can propose purchases, human operators retain absolute cryptographic control over their funds.

## 🚀 Live Demo & Evaluation
**Judges do not need to run this locally!** We have built a 1-Click interactive simulator directly into the dashboard.

* **Live Dashboard:** [Insert Your Vercel URL Here]
* **How to test:**
  1. Open the dashboard and click the **`🔒 Enroll Passkey`** button to bind your device.
  2. Click the **`🤖 Simulate Agent ($90)`** button in the header. This triggers our internal AI pipeline to autonomously propose a high-value gaming headset purchase.
  3. The order will escalate to `AWAITING BIOMETRICS`. Click **`🛡️ Approve (Passkey)`** to cryptographically sign the transaction.
  4. The system verifies the signature and instantly captures the funds via the **PayPal Sandbox API**.

---

## 🧠 Core Technology & Hackathon Requirements

### 1. PayPal Developer Platform (Sandbox)
We integrated the robust **PayPal Orders API (v2)** to handle all real-world financial state changes.
* **Order Creation & Authorization:** When an agent proposes a purchase within budget, Nexus creates a PayPal authorization hold.
* **Capture via Biometrics:** Once the human operator verifies the transaction via WebAuthn/Passkeys, Nexus executes the PayPal Capture endpoint to settle the funds.
* **Voiding:** If rejected, Nexus instantly voids the PayPal authorization to free up the user's funds.

### 2. AI Tool Integration (Google Gemini)
We leveraged the **Google Gemini API** to simulate the autonomous AI purchasing agent. 
* The AI dynamically evaluates the user's defined "Warrants" (budget constraints and allowed categories).
* It autonomously negotiates and proposes valid transactions to the Nexus Gateway.
* *Note: For ease of judge evaluation, the "Simulate Agent" button runs a deterministic mock of this AI pipeline without requiring API keys.*

### 3. Additional Sponsor Integration
* **Render:** Our secure FastAPI backend and SQLite cryptographic ledger are hosted and deployed seamlessly on Render.

---

## 🏗️ Architecture & Features
1. **Passkey (WebAuthn) Approvals:** Replaces vulnerable passwords with hardware-backed cryptographic signatures (FaceID / TouchID / Windows Hello).
2. **Immutable Ledger:** Every lifecycle event (Proposal, Escalation, Approval, Capture) is hashed and chained into an SQLite ledger using Ed25519 signatures. 
3. **Tamper-Evident Audit Trails:** Anyone can click `Export Proof` to download `nexus_audit_proof.json` and verify the integrity of the transaction chain completely offline.

---

## 💻 Local Setup (For Offline Auditing)
If you wish to run the backend locally or verify the cryptographic chain:

```bash
# 1. Clone the repo
git clone [https://github.com/Kislay20/nexus-zero-trust.git](https://github.com/Kislay20/nexus-zero-trust.git)
cd nexus-zero-trust

# 2. Install dependencies
pip install -r requirements.txt

# 3. Verify the Audit Proof (Offline)
python nexus_verify.py nexus_audit_proof.json
