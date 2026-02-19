package com.example.lip_app

import android.os.Bundle
import android.util.Base64
import androidx.annotation.NonNull
import com.yubico.yubikit.android.YubiKitManager
import com.yubico.yubikit.android.transport.nfc.NfcConfiguration
import com.yubico.yubikit.android.transport.nfc.NfcYubiKeyDevice
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.fido.ctap.Ctap2Session
import com.yubico.yubikit.fido.Cbor
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.security.MessageDigest

class MainActivity: FlutterActivity() {
    private val CHANNEL = "com.example.lip_app/fido"
    private lateinit var yubiKitManager: YubiKitManager
    private var pendingResult: MethodChannel.Result? = null

    // Securely read the domain from the Gradle BuildConfig!
    private val RP_ID = BuildConfig.RP_ID
    private val ORIGIN = "https://$RP_ID"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        yubiKitManager = YubiKitManager(this)
    }

    override fun configureFlutterEngine(@NonNull flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL).setMethodCallHandler { call, result ->
            val optionsJson = call.argument<String>("options") ?: "{}"
            if (call.method == "register") {
                pendingResult = result
                startNfcRegistration(optionsJson)
            } else if (call.method == "authenticate") {
                pendingResult = result
                startNfcAuthentication(optionsJson)
            } else {
                result.notImplemented()
            }
        }
    }

    // ==========================================
    // REGISTRATION (MAKE CREDENTIAL)
    // ==========================================
    private fun startNfcRegistration(optionsJson: String) {
        try {
            yubiKitManager.startNfcDiscovery(NfcConfiguration(), this) { device: NfcYubiKeyDevice ->
                device.requestConnection(SmartCardConnection::class.java) { result ->
                    try {
                        val json = JSONObject(optionsJson)
                        val ctap2Session = Ctap2Session(result.value)
                        
                        // 1. Client Data (Using Secure ORIGIN)
                        val challengeStr = json.getString("challenge")
                        val clientDataString = "{\"type\":\"webauthn.create\",\"challenge\":\"$challengeStr\",\"origin\":\"$ORIGIN\",\"crossOrigin\":false}"
                        val clientDataHash = MessageDigest.getInstance("SHA-256").digest(clientDataString.toByteArray())

                        // 2. RP Map (Using Secure RP_ID)
                        val rpJson = json.getJSONObject("rp")
                        val rpMap = mapOf("id" to RP_ID, "name" to rpJson.getString("name"))

                        // 3. User Map 
                        val userJson = json.getJSONObject("user")
                        val userIdBytes = Base64.decode(userJson.getString("id"), Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
                        val userMap = mapOf("id" to userIdBytes, "name" to userJson.getString("name"), "displayName" to userJson.getString("displayName"))

                        // 4. Algorithms
                        val paramsJson = json.getJSONArray("pubKeyCredParams")
                        val paramsList = mutableListOf<Map<String, Any>>()
                        for (i in 0 until paramsJson.length()) {
                            val p = paramsJson.getJSONObject(i)
                            paramsList.add(mapOf("type" to p.getString("type"), "alg" to p.getInt("alg")))
                        }

                        // 5. Fire FIDO2 MakeCredential 
                        val optionsMap = mapOf("rk" to false, "up" to true)
                        val credentialData = ctap2Session.makeCredential(
                            clientDataHash, rpMap, userMap, paramsList as List<Map<String, *>>, 
                            null, null, optionsMap, null, null, null, null
                        )

                        // 6. Extract Credential ID 
                        val authData = credentialData.authenticatorData
                        val credIdLen = ((authData[53].toInt() and 0xFF) shl 8) or (authData[54].toInt() and 0xFF)
                        val credId = authData.copyOfRange(55, 55 + credIdLen)
                        val idBase64 = Base64.encodeToString(credId, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

                        // 7. Manually CBOR encode the Attestation Object
                        val attObjMap = mapOf(
                            "fmt" to credentialData.format,
                            "authData" to credentialData.authenticatorData,
                            "attStmt" to credentialData.attestationStatement
                        )
                        val baos = ByteArrayOutputStream()
                        Cbor.encodeTo(baos, attObjMap)
                        
                        val attestationB64 = Base64.encodeToString(baos.toByteArray(), Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
                        val clientDataB64 = Base64.encodeToString(clientDataString.toByteArray(), Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

                        val jsonResp = JSONObject()
                        jsonResp.put("id", idBase64)
                        jsonResp.put("rawId", idBase64)
                        jsonResp.put("type", "public-key")
                        
                        val responseObj = JSONObject()
                        responseObj.put("clientDataJSON", clientDataB64)
                        responseObj.put("attestationObject", attestationB64)
                        jsonResp.put("response", responseObj)

                        runOnUiThread {
                            pendingResult?.success(jsonResp.toString())
                            pendingResult = null
                        }
                    } catch (e: Exception) {
                        runOnUiThread {
                            pendingResult?.error("YUBIKIT_ERR", "Registration Hardware rejection: ${e.message}", null)
                            pendingResult = null
                        }
                    } finally {
                        runOnUiThread { yubiKitManager.stopNfcDiscovery(this@MainActivity) }
                    }
                }
            }
        } catch (e: Exception) {
            pendingResult?.error("NFC_ERR", "NFC failed to start", null)
            pendingResult = null
        }
    }

    // ==========================================
    // LOGIN (GET ASSERTION)
    // ==========================================
    private fun startNfcAuthentication(optionsJson: String) {
        try {
            yubiKitManager.startNfcDiscovery(NfcConfiguration(), this) { device: NfcYubiKeyDevice ->
                device.requestConnection(SmartCardConnection::class.java) { result ->
                    try {
                        val json = JSONObject(optionsJson)
                        val ctap2Session = Ctap2Session(result.value)

                        // 1. Client Data (Using Secure ORIGIN)
                        val challengeStr = json.getString("challenge")
                        val clientDataString = "{\"type\":\"webauthn.get\",\"challenge\":\"$challengeStr\",\"origin\":\"$ORIGIN\",\"crossOrigin\":false}"
                        val clientDataHash = MessageDigest.getInstance("SHA-256").digest(clientDataString.toByteArray())

                        // 2. Allow List 
                        val allowList = mutableListOf<Map<String, Any>>()
                        if (json.has("allowCredentials")) {
                            val credsArray = json.getJSONArray("allowCredentials")
                            for (i in 0 until credsArray.length()) {
                                val c = credsArray.getJSONObject(i)
                                val idBytes = Base64.decode(c.getString("id"), Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
                                allowList.add(mapOf("type" to c.getString("type"), "id" to idBytes))
                            }
                        }

                        // 3. Fire FIDO2 GetAssertion (Using Secure RP_ID)
                        val optionsMap = mapOf("up" to true)
                        val assertions = ctap2Session.getAssertions(
                            RP_ID,
                            clientDataHash,
                            if (allowList.isEmpty()) null else allowList as List<Map<String, *>>,
                            null,
                            optionsMap,
                            null,
                            null,
                            null
                        )

                        if (assertions.isEmpty()) {
                            throw Exception("No credentials found on this YubiKey.")
                        }

                        // 4. Extract data from the YubiKey's assertion
                        val assertion = assertions[0] 
                        
                        val credIdBytes = if (assertion.credential != null) {
                            assertion.credential!!["id"] as ByteArray
                        } else {
                            allowList[0]["id"] as ByteArray
                        }
                        
                        val idBase64 = Base64.encodeToString(credIdBytes, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
                        val authDataB64 = Base64.encodeToString(assertion.authenticatorData, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
                        val signatureB64 = Base64.encodeToString(assertion.signature, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
                        val clientDataB64 = Base64.encodeToString(clientDataString.toByteArray(), Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

                        // 5. Build the strict JSON structure
                        val jsonResp = JSONObject()
                        jsonResp.put("id", idBase64)
                        jsonResp.put("rawId", idBase64)
                        jsonResp.put("type", "public-key")

                        val responseObj = JSONObject()
                        responseObj.put("clientDataJSON", clientDataB64)
                        responseObj.put("authenticatorData", authDataB64)
                        responseObj.put("signature", signatureB64)

                        if (assertion.user != null && assertion.user!!["id"] != null) {
                            val userHandleBytes = assertion.user!!["id"] as ByteArray
                            responseObj.put("userHandle", Base64.encodeToString(userHandleBytes, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP))
                        }

                        jsonResp.put("response", responseObj)

                        runOnUiThread {
                            pendingResult?.success(jsonResp.toString())
                            pendingResult = null
                        }
                    } catch (e: Exception) {
                        runOnUiThread {
                            pendingResult?.error("YUBIKIT_ERR", "Login Hardware rejection: ${e.message}", null)
                            pendingResult = null
                        }
                    } finally {
                        runOnUiThread { yubiKitManager.stopNfcDiscovery(this@MainActivity) }
                    }
                }
            }
        } catch (e: Exception) {
            pendingResult?.error("NFC_ERR", "NFC failed to start", null)
            pendingResult = null
        }
    }

    private fun runOnUiThread(action: () -> Unit) {
        CoroutineScope(Dispatchers.Main).launch { action() }
    }
}