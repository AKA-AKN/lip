Here is your complete **README.md** file formatted properly in Markdown.\
You can copy this entire content and save it directly as `README.md`.

* * * * *

True Passwordless FIDO2 Integration
===================================

(Discoverable / Resident Keys)
------------------------------

This branch contains an **enterprise-grade, hardware-bound FIDO2 integration**.

It achieves **True Passwordless Login (Usernameless Login)** by bypassing high-level Android APIs and communicating directly with the secure enclave of a physical **YubiKey** over NFC.

Unlike standard implementations, this architecture forces the creation of:

-   **Discoverable Credentials (Resident Keys)**

-   Strict **FIDO2.1 PIN-bound User Verification**

* * * * *

🔑 Discoverable vs. Non-Discoverable Keys
=========================================

Non-Discoverable (Standard)
---------------------------

-   The server stores the encrypted private key.

-   The user must type their username to fetch it.

-   The YubiKey decrypts and signs it.

-   **Username is required.**

Discoverable (This Branch)
--------------------------

-   The YubiKey permanently stores:

    -   The Private Key

    -   The Domain (`RP_ID`)

    -   The User ID

-   All stored directly inside the hardware's internal flash memory.

### ✅ The Result

During login, the user types **nothing**.\
They simply tap the key, and the hardware identifies them automatically.

* * * * *

🛡️ Architecture & the FIDO2.1 PIN Protocol
===========================================

Because this integration writes identities directly into the physical memory of the hardware, **FIDO2.1 security standards block this action by default**, resulting in:

-   `CTAP error: PUAT_REQUIRED (0x36)`

-   `MISSING_PARAMETER (0x14)`

To securely bypass this and write credentials to the key, the app implements the:

ClientPIN Protocol (PinUvAuthProtocolV2)
----------------------------------------

via the Yubico SDK.

### Flow Overview

1.  **Flutter**

    -   Prompts the user for their physical YubiKey PIN.

2.  **Kotlin (Hardware Bridge)**

    -   Takes the PIN.

    -   Auto-negotiates `PinUvAuthProtocolV2` with the YubiKey.

    -   Requests a VIP Token explicitly bound to:

        -   The domain (`RP_ID`)

        -   The specific action (`MakeCredential` or `GetAssertion`)

3.  **YubiKey**

    -   Verifies the PIN.

    -   Issues the token.

    -   Accepts the `rk=true` (Resident Key) command.

    -   Securely stores the credential in hardware.

* * * * *

⚙️ Step-by-Step Environment Setup
=================================

For security reasons, no domains or hashes are hardcoded in this repository.

You must configure **three separate environment files** before running the app.

* * * * *

1️⃣ Flutter Environment (`/.env`)
---------------------------------

Create a `.env` file in the root of your Flutter project:

```
API_BASE_URL=https://your-production-domain.com

```

For local Android Emulator testing, use:

```
API_BASE_URL=http://10.0.2.2:8000

```

* * * * *

2️⃣ Android Native Environment (`/android/local.properties`)
------------------------------------------------------------

Android native files (e.g., `AndroidManifest.xml`, `MainActivity.kt`) cannot read the Flutter `.env`.

We inject the domain at compile-time using Gradle.

Add this to:

```
android/local.properties

```

```
rp_id=your-production-domain.com

```

* * * * *

3️⃣ Python Backend Environment (Server `/.env`)
-----------------------------------------------

The FIDO2 WebAuthn standard requires the backend to verify the Android App's Cryptographic Facet ID.

Add this to your server `.env`:

```
RP_ID=your-production-domain.com
RP_NAME="Your App Name"
ANDROID_FACET_ID=android:apk-key-hash:YOUR_SHA256_FINGERPRINT_BASE64_URL_ENCODED

```

* * * * *

🛠️ Core Implementation Details
===============================

🔐 Registration (`auth_service.dart`)
-------------------------------------

Before sending WebAuthn options to the hardware, the app injects:

```
requireResidentKey: true
residentKey: 'required'

```

This forces creation of a **Discoverable (Resident) Credential**.

* * * * *

🔓 Login (`auth_service.dart`)
------------------------------

During login:

-   An empty `allowCredentials` list is sent to the YubiKey.

This commands the hardware to:

> Search its own internal memory for a credential matching the current `RP_ID`.

This enables **true usernameless login**.

* * * * *

🔗 Hardware Bridge (`MainActivity.kt`)
--------------------------------------

-   Uses Yubico's `Ctap2Session`

-   Communicates directly via CBOR mapping

-   Bypasses Android OS-level domain validation blocks

-   Enables direct low-level FIDO2 communication

* * * * *

📡 NFC Timing Requirements
--------------------------

The YubiKey requires approximately:

> **2--3 seconds of perfectly still NFC contact**

This is necessary to:

-   Compute RSA/ECDSA keypairs

-   Verify the PIN

-   Write credentials to secure flash

### ⚠️ Important

Removing the key too early results in:

```
Tag was lost

```

hardware exception.

✅ Result
--------

You now have:

-   True Passwordless

-   Hardware-bound authentication

-   Domain-bound resident credentials

-   Strict FIDO2.1 PIN verification

-   Secure environment separation across Flutter, Android, and Backend

* * * * *

**End of README**