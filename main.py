import os
import json
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from webauthn import (
    generate_registration_options, 
    options_to_json,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    ResidentKeyRequirement,
)

load_dotenv()

app = FastAPI()

# Read from .env
RP_ID = os.getenv("RP_ID", "localhost")
RP_NAME = os.getenv("RP_NAME", "Lip App Authentication")
ANDROID_FACET_ID = os.getenv("ANDROID_FACET_ID", "")

ORIGIN = [
    f"https://{RP_ID}",
    ANDROID_FACET_ID
]

# Mock Databases
db_users = {}      # Maps username -> dict
db_challenges = {} # Maps username (or 'discoverable_login') -> challenge string

class RegisterFinishRequest(BaseModel):
    username: str
    response_data: dict

class AuthenticateFinishRequest(BaseModel):
    response_data: dict # Notice: NO USERNAME REQUIRED!

# ==============================
# 1. DISCOVERABLE REGISTRATION
# ==============================

@app.post("/generate-registration-options")
def generate_registration_challenge(username: str):
    user_id = os.urandom(32) # In production, this is the user's UUID in your DB

    try:
        options = generate_registration_options(
            rp_id=RP_ID,
            rp_name=RP_NAME,
            user_id=user_id,
            user_name=username,
            authenticator_selection=AuthenticatorSelectionCriteria(
                authenticator_attachment=None, 
                resident_key=ResidentKeyRequirement.REQUIRED, # <--- CHANGED: Force Resident Key
                user_verification=UserVerificationRequirement.DISCOURAGED, 
            ),
        )

        db_challenges[username] = options.challenge
        print(f"Registration challenge generated for {username}")
        return json.loads(options_to_json(options))

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/verify-registration")
def verify_registration(request: RegisterFinishRequest):
    try:
        expected_challenge = db_challenges.get(request.username)
        if not expected_challenge:
            raise HTTPException(status_code=400, detail="Challenge not found")

        verification = verify_registration_response(
            credential=request.response_data,
            expected_challenge=expected_challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            require_user_verification=False
        )

        # Save the hardware details to the user
        db_users[request.username] = {
            "credential_id": verification.credential_id.hex(),
            "public_key": verification.credential_public_key.hex(),
            "sign_count": verification.sign_count,
            "user_id": request.response_data.get("response", {}).get("userHandle") # Store the internal YubiKey ID
        }

        print(f"✅ VERIFIED! Resident Key saved for {request.username}")
        return {"status": "success", "message": "YubiKey officially registered!"}

    except Exception as e:
        print(f"❌ Registration Verification Failed: {str(e)}")
        return JSONResponse(status_code=400, content={"status": "failed", "detail": str(e)})

# ==============================
# 2. DISCOVERABLE LOGIN (Passwordless)
# ==============================

@app.post("/generate-discoverable-auth-options")
def generate_discoverable_challenge():
    try:
        # Notice: allow_credentials is EMPTY! The YubiKey must find it.
        options = generate_authentication_options(
            rp_id=RP_ID,
            user_verification=UserVerificationRequirement.DISCOURAGED,
        )

        # Since we don't know who is logging in yet, we save the challenge under a generic key
        db_challenges['discoverable_login'] = options.challenge
        print(f"Discoverable Login challenge generated!")
        return json.loads(options_to_json(options))

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/verify-authentication")
def verify_auth(request: AuthenticateFinishRequest):
    try:
        expected_challenge = db_challenges.get('discoverable_login')
        
        # 1. Who is logging in? The YubiKey gives us the Credential ID.
        incoming_cred_id_hex = request.response_data.get("id")
        if not incoming_cred_id_hex:
            raise HTTPException(status_code=400, detail="No Credential ID provided by YubiKey")
        
        # 2. Look up the user in our database using the Credential ID
        matched_username = None
        matched_user_data = None
        for uname, data in db_users.items():
            # Convert python hex to base64url format for matching, or just match hex
            # The webauthn library handles the formats internally usually, but let's do a simple lookup.
            # Easiest way: just pass the user's stored public key to verify_authentication_response and let it fail if it's wrong.
            pass
            
        # Proper lookup: decode base64url ID from incoming
        import base64
        incoming_bytes = base64.urlsafe_b64decode(incoming_cred_id_hex + '==')
        incoming_hex = incoming_bytes.hex()

        for uname, data in db_users.items():
            if data["credential_id"] == incoming_hex:
                matched_username = uname
                matched_user_data = data
                break
        
        if not matched_user_data:
            raise HTTPException(status_code=404, detail="Unrecognized YubiKey. Please register first.")

        # 3. Verify the cryptographic signature using the public key we just found
        verification = verify_authentication_response(
            credential=request.response_data,
            expected_challenge=expected_challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            credential_public_key=bytes.fromhex(matched_user_data["public_key"]),
            credential_current_sign_count=matched_user_data["sign_count"],
            require_user_verification=False
        )

        # Update the signature count to prevent replay attacks
        db_users[matched_username]["sign_count"] = verification.new_sign_count

        print(f"🔓 TRUE PASSWORDLESS LOGIN SUCCESSFUL for: {matched_username}")
        return {"status": "success", "message": f"Welcome back, {matched_username}!"}

    except Exception as e:
        print(f"❌ Login Failed: {str(e)}")
        return JSONResponse(status_code=400, content={"status": "failed", "detail": str(e)})

@app.get("/.well-known/assetlinks.json")
def asset_links():
    return JSONResponse([{
        "relation": ["delegate_permission/common.handle_all_urls", "delegate_permission/common.get_login_creds"],
        "target": {"namespace": "android_app", "package_name": "com.example.lip_app", "sha256_cert_fingerprints": [ANDROID_FACET_ID.replace("android:apk-key-hash:", "")]}
    }])