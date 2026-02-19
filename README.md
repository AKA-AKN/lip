# Native FIDO2 Hardware Integration (Non-Discoverable Keys)

This branch contains a custom, hardware-level integration for FIDO2/WebAuthn using Flutter, Kotlin, and Python. 

It intentionally bypasses the high-level Android `CredentialManager` API to communicate directly with the secure enclave of a physical YubiKey over NFC via CTAP2 (Client to Authenticator Protocol). This approach ensures strict control over cryptography, eliminates OS-level black-box errors, and forces the generation of **Non-Discoverable (Non-Resident) Keys**.

## Architecture Flow

1.  **Flutter (UI/Network):** Requests a challenge from the Python Backend. Passes the WebAuthn JSON options to the Android layer via a `MethodChannel`.
2.  **Kotlin (Hardware Bridge):** Parses the JSON, bypasses software checks, and uses the YubiKit `Ctap2Session` to send binary CBOR instructions directly to the physical NFC chip.
3.  **YubiKey (Cryptography):** Generates an ECDSA/RSA keypair. It encrypts (wraps) the private key, stores nothing in its own memory (Non-Discoverable), and returns the cryptographic signature to Kotlin.
4.  **Python (Verification):** Receives the raw Base64URL signature, verifies it against the FIDO2 standard using the `webauthn` library, and saves the public key to the database.

## System Prerequisites
* **Android SDK:** Minimum SDK 21 (Lollipop).
* **Dependencies:** * Yubico Android SDK 3.0.1 (`yubikit:android`, `yubikit:core`, `yubikit:fido`)
    * Flutter `http` & `flutter_dotenv`
    * Python `fastapi`, `webauthn`

## Core Implementation Steps

### 1. The Python Backend (FastAPI)
The backend manages challenges and verifies hardware signatures.
* **Registration:** Generates options using `ResidentKeyRequirement.DISCOURAGED` to explicitly request a non-discoverable key.
* **Authentication:** Generates a challenge and explicitly provides the `allow_credentials` array (containing the `credential_id` generated during registration) so the YubiKey knows which encrypted private key to decrypt.

### 2. The Flutter Interceptor (`auth_service.dart`)
The Flutter layer acts as an interceptor before handing data to the hardware.
* The raw JSON from Python is intercepted and forcibly overwritten to ensure cross-platform FIDO2 attachment and discouraged resident keys.
* It communicates with Android via `MethodChannel('com.example.lip_app/fido')`.

### 3. The Kotlin Hardware Bridge (`MainActivity.kt`)
This is the core native engine. It drops the high-level `WebAuthnClient` in favor of `Ctap2Session` to prevent OS-level domain validation blocking (e.g., rejecting IP addresses during development).
* **Hashing:** Manually constructs the `clientDataJSON` and hashes it via SHA-256.
* **MakeCredential / GetAssertion:** Passes raw primitive Maps (not strict objects) directly to the YubiKey applet.
* **Byte Extraction:** Manually extracts the binary `credentialId` from the raw `authenticatorData` using WebAuthn byte offsets (starts at byte 55).
* **CBOR Encoding:** Manually packages the `fmt`, `authData`, and `attStmt` into a CBOR map, encodes it to Base64URL, and builds the strict JSON structure required by the Python server.

### Important Hardware Behavior
* **NFC Timing:** The YubiKey requires ~2-3 seconds of perfectly still contact with the NFC antenna to compute the RSA/ECDSA keypairs. Removing the key too early results in a `Tag was lost` hardware exception.

### Environment Setup
To run this project, create `.env` files in both the Flutter and Python roots containing your `API_BASE_URL` and `RP_ID` respectively.