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
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    ResidentKeyRequirement,
    PublicKeyCredentialDescriptor,
)

app = FastAPI()

# ==============================
# CONFIGURATION & MOCK DATABASE
# ==============================

RP_ID = os.getenv("RP_ID", "localhost")
RP_NAME = os.getenv("RP_NAME", "Local Test App")
ANDROID_FACET_ID = os.getenv("ANDROID_FACET_ID", "")

ORIGIN = [
    f"https://{RP_ID}",
    ANDROID_FACET_ID
]

db_users = {}
db_challenges = {}

class RegisterFinishRequest(BaseModel):
    username: str
    response_data: dict

class AuthenticateFinishRequest(BaseModel):
    username: str
    response_data: dict

# ==============================
# 1. DISCOVERABLE REGISTRATION
# ==============================

@app.post("/generate-registration-options")
def generate_registration_challenge(username: str):
    user_id = os.urandom(32)

    try:
        # Simplest possible FIDO2 configuration
        options = generate_registration_options(
            rp_id=RP_ID,
            rp_name=RP_NAME,
            user_id=user_id,
            user_name=username,
            authenticator_selection=AuthenticatorSelectionCriteria(
                authenticator_attachment=None, # DO NOT restrict to cross-platform
                resident_key=ResidentKeyRequirement.DISCOURAGED, # Standard U2F
                user_verification=UserVerificationRequirement.PREFERRED, # Let OS decide PIN
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
            raise HTTPException(status_code=400, detail="Challenge not found or expired")

        verification = verify_registration_response(
            credential=request.response_data,
            expected_challenge=expected_challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
        )

        db_users[request.username] = {
            "credential_id": verification.credential_id.hex(),
            "public_key": verification.credential_public_key.hex(),
            "sign_count": verification.sign_count,
        }

        print(f"✅ VERIFIED! Credential ID saved for {request.username}")
        return {"status": "success", "message": "YubiKey officially registered!"}

    except Exception as e:
        print(f"❌ Registration Verification Failed: {str(e)}")
        return JSONResponse(status_code=400, content={"status": "failed", "detail": str(e)})


# ==============================
# 2. DISCOVERABLE LOGIN
# ==============================

@app.post("/generate-authentication-options")
def generate_auth_challenge(username: str):
    user = db_users.get(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found. Register first.")

    try:
        # Provide the ID, let OS handle transports
        options = generate_authentication_options(
            rp_id=RP_ID,
            allow_credentials=[
                PublicKeyCredentialDescriptor(id=bytes.fromhex(user["credential_id"]))
            ],
            user_verification=UserVerificationRequirement.PREFERRED, # Let OS decide PIN
        )

        db_challenges[username] = options.challenge
        print(f"Login challenge generated for {username}")
        return json.loads(options_to_json(options))

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/verify-authentication")
def verify_auth(request: AuthenticateFinishRequest):
    try:
        user = db_users.get(request.username)
        expected_challenge = db_challenges.get(request.username)

        if not user or not expected_challenge:
            raise HTTPException(status_code=400, detail="Invalid session")

        verification = verify_authentication_response(
            credential=request.response_data,
            expected_challenge=expected_challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            credential_public_key=bytes.fromhex(user["public_key"]),
            credential_current_sign_count=user["sign_count"],
        )

        db_users[request.username]["sign_count"] = verification.new_sign_count

        print(f"🔓 LOGIN SUCCESSFUL for {request.username}")
        return {"status": "success", "message": "Login Successful!"}

    except Exception as e:
        print(f"❌ Login Failed: {str(e)}")
        return JSONResponse(status_code=400, content={"status": "failed", "detail": str(e)})

@app.get("/.well-known/assetlinks.json")
def asset_links():
    return JSONResponse([{
        "relation": ["delegate_permission/common.handle_all_urls", "delegate_permission/common.get_login_creds"],
        "target": {"namespace": "android_app", "package_name": "com.example.lip_app", "sha256_cert_fingerprints": ["2E:B7:C3:7C:69:EE:62:14:FA:53:95:6C:60:73:A6:7A:4C:59:2D:BC:89:AF:74:17:4A:F4:50:6C:C2:DE:DD:F6"]}
    }])

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)