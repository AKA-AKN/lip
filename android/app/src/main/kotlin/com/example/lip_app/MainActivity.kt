package com.example.lip_app

import android.os.Bundle
import android.util.Base64
import androidx.annotation.NonNull
import com.yubico.yubikit.android.YubiKitManager
import com.yubico.yubikit.android.transport.nfc.NfcConfiguration
import com.yubico.yubikit.android.transport.nfc.NfcYubiKeyDevice
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.fido.ctap.Ctap2Session
import com.yubico.yubikit.fido.ctap.ClientPin 
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV1 
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV2
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
            val pin = call.argument<String>("pin") ?: "" 
            
            if (call.method == "register") {
                pendingResult = result
                startNfcRegistration(optionsJson, pin)
            } else if (call.method == "authenticate") {
                pendingResult = result
                startNfcAuthentication(optionsJson, pin)
            } else {
                result.notImplemented()
            }
        }
    }

    // ==========================================
    // REGISTRATION (MAKE CREDENTIAL)
    // ==========================================
    private fun startNfcRegistration(optionsJson: String, pin: String) {
        try {
            yubiKitManager.startNfcDiscovery(NfcConfiguration(), this) { device: NfcYubiKeyDevice ->
                device.requestConnection(SmartCardConnection::class.java) { result ->
                    try {
                        val json = JSONObject(optionsJson)
                        val ctap2Session = Ctap2Session(result.value)
                        
                        val challengeStr = json.getString("challenge")
                        val clientDataString = "{\"type\":\"webauthn.create\",\"challenge\":\"$challengeStr\",\"origin\":\"$ORIGIN\",\"crossOrigin\":false}"
                        val clientDataHash = MessageDigest.getInstance("SHA-256").digest(clientDataString.toByteArray())

                        val rpJson = json.getJSONObject("rp")
                        val rpMap = mapOf("id" to RP_ID, "name" to rpJson.getString("name"))

                        val userJson = json.getJSONObject("user")
                        val userIdBytes = Base64.decode(userJson.getString("id"), Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
                        val userMap = mapOf("id" to userIdBytes, "name" to userJson.getString("name"), "displayName" to userJson.getString("displayName"))

                        val paramsJson = json.getJSONArray("pubKeyCredParams")
                        val paramsList = mutableListOf<Map<String, Any>>()
                        for (i in 0 until paramsJson.length()) {
                            val p = paramsJson.getJSONObject(i)
                            paramsList.add(mapOf("type" to p.getString("type"), "alg" to p.getInt("alg")))
                        }

                        // --- THE SECURE PIN NEGOTIATOR ---
                        var pinUvAuthParam: ByteArray? = null
                        var pinUvProtocolVersion: Int? = null

                        if (pin.isNotEmpty()) {
                            val protocols = ctap2Session.cachedInfo.pinUvAuthProtocols
                            val pinProtocol = if (protocols.contains(2)) PinUvAuthProtocolV2() else PinUvAuthProtocolV1()
                            
                            val clientPin = ClientPin(ctap2Session, pinProtocol)
                            
                            // EXPLICITLY BIND TO MAKECREDENTIAL (PIN_PERMISSION_MC) AND DOMAIN
                            val pinToken = clientPin.getPinToken(pin.toCharArray(), ClientPin.PIN_PERMISSION_MC, RP_ID)
                            pinUvAuthParam = pinProtocol.authenticate(pinToken, clientDataHash)
                            pinUvProtocolVersion = pinProtocol.version
                        }

                        val optionsMap = mapOf("rk" to true, "up" to true) // RESIDENT KEY IS TRUE
                        
                        val credentialData = ctap2Session.makeCredential(
                            clientDataHash, rpMap, userMap, paramsList as List<Map<String, *>>, 
                            null, null, optionsMap, 
                            pinUvAuthParam, pinUvProtocolVersion, 
                            null, null
                        )

                        val authData = credentialData.authenticatorData
                        val credIdLen = ((authData[53].toInt() and 0xFF) shl 8) or (authData[54].toInt() and 0xFF)
                        val credId = authData.copyOfRange(55, 55 + credIdLen)
                        val idBase64 = Base64.encodeToString(credId, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

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
                        
                        // Pass the YubiKey's internal User Handle back up
                        responseObj.put("userHandle", Base64.encodeToString(userIdBytes, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP))
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
    private fun startNfcAuthentication(optionsJson: String, pin: String) {
        try {
            yubiKitManager.startNfcDiscovery(NfcConfiguration(), this) { device: NfcYubiKeyDevice ->
                device.requestConnection(SmartCardConnection::class.java) { result ->
                    try {
                        val json = JSONObject(optionsJson)
                        val ctap2Session = Ctap2Session(result.value)

                        val challengeStr = json.getString("challenge")
                        val clientDataString = "{\"type\":\"webauthn.get\",\"challenge\":\"$challengeStr\",\"origin\":\"$ORIGIN\",\"crossOrigin\":false}"
                        val clientDataHash = MessageDigest.getInstance("SHA-256").digest(clientDataString.toByteArray())

                        val allowList = mutableListOf<Map<String, Any>>()
                        if (json.has("allowCredentials")) {
                            val credsArray = json.getJSONArray("allowCredentials")
                            for (i in 0 until credsArray.length()) {
                                val c = credsArray.getJSONObject(i)
                                val idBytes = Base64.decode(c.getString("id"), Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
                                allowList.add(mapOf("type" to c.getString("type"), "id" to idBytes))
                            }
                        }

                        // --- THE SECURE PIN NEGOTIATOR ---
                        var pinUvAuthParam: ByteArray? = null
                        var pinUvProtocolVersion: Int? = null

                        if (pin.isNotEmpty()) {
                            val protocols = ctap2Session.cachedInfo.pinUvAuthProtocols
                            val pinProtocol = if (protocols.contains(2)) PinUvAuthProtocolV2() else PinUvAuthProtocolV1()
                            
                            val clientPin = ClientPin(ctap2Session, pinProtocol)
                            
                            // EXPLICITLY BIND TO GETASSERTION (PIN_PERMISSION_GA) AND DOMAIN
                            val pinToken = clientPin.getPinToken(pin.toCharArray(), ClientPin.PIN_PERMISSION_GA, RP_ID)
                            pinUvAuthParam = pinProtocol.authenticate(pinToken, clientDataHash)
                            pinUvProtocolVersion = pinProtocol.version
                        }

                        val optionsMap = mapOf("up" to true)
                        
                        val assertions = ctap2Session.getAssertions(
                            RP_ID,
                            clientDataHash,
                            if (allowList.isEmpty()) null else allowList as List<Map<String, *>>,
                            null,
                            optionsMap,
                            pinUvAuthParam, pinUvProtocolVersion, 
                            null
                        )

                        if (assertions.isEmpty()) {
                            throw Exception("No credentials found on this YubiKey.")
                        }

                        val assertion = assertions[0] 
                        
                        val credIdBytes = if (assertion.credential != null) {
                            assertion.credential!!["id"] as ByteArray
                        } else if (allowList.isNotEmpty()) {
                            allowList[0]["id"] as ByteArray
                        } else {
                            throw Exception("YubiKey did not return a credential ID.")
                        }
                        
                        val idBase64 = Base64.encodeToString(credIdBytes, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
                        val authDataB64 = Base64.encodeToString(assertion.authenticatorData, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
                        val signatureB64 = Base64.encodeToString(assertion.signature, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
                        val clientDataB64 = Base64.encodeToString(clientDataString.toByteArray(), Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

                        val jsonResp = JSONObject()
                        jsonResp.put("id", idBase64)
                        jsonResp.put("rawId", idBase64)
                        jsonResp.put("type", "public-key")

                        val responseObj = JSONObject()
                        responseObj.put("clientDataJSON", clientDataB64)
                        responseObj.put("authenticatorData", authDataB64)
                        responseObj.put("signature", signatureB64)

                        // For discoverable login, the YubiKey sends back the user ID it found!
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