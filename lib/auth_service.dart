import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:flutter/services.dart';
import 'package:flutter_dotenv/flutter_dotenv.dart';

class AuthService {
  static String baseUrl =
      dotenv.env['API_BASE_URL'] ??
      (throw Exception('FATAL: API_BASE_URL is missing from .env file!'));

  static const MethodChannel _channel = MethodChannel(
    'com.example.lip_app/fido',
  );

  // ==========================================
  // 1. DISCOVERABLE REGISTRATION
  // ==========================================
  Future<void> registerYubikey(String username, String pin) async {
    try {
      print("Starting Native Discoverable Registration...");
      final optionsRes = await http.post(
        Uri.parse('$baseUrl/generate-registration-options?username=$username'),
      );

      final Map<String, dynamic> decoded = jsonDecode(optionsRes.body);

      if (decoded['user'] != null) {
        decoded['user']['displayName'] ??= decoded['user']['name'] ?? 'User';
      }

      // FORCE RESIDENT KEY
      decoded['authenticatorSelection'] = {
        'authenticatorAttachment': 'cross-platform',
        'requireResidentKey': true,
        'residentKey': 'required',
      };

      decoded['attestation'] = 'none';
      decoded['excludeCredentials'] ??= [];

      final String modifiedOptionsJson = jsonEncode(decoded);

      // Pass the PIN into the channel
      final String resultJson = await _channel.invokeMethod('register', {
        'options': modifiedOptionsJson,
        'pin': pin,
      });

      final payload = {
        "username": username,
        "response_data": jsonDecode(resultJson),
      };

      final verifyRes = await http.post(
        Uri.parse('$baseUrl/verify-registration'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode(payload),
      );

      if (verifyRes.statusCode != 200) throw Exception("Server rejected key");
      print("✅ Native Discoverable Registration Success!");
    } catch (e) {
      print("❌ Native Registration Error: $e");
      rethrow;
    }
  }

  // ==========================================
  // 2. DISCOVERABLE LOGIN (PASSWORDLESS)
  // ==========================================
  Future<String> loginDiscoverable(String pin) async {
    try {
      print("Starting True Passwordless Login...");

      // We do NOT send a username to the server!
      final optionsRes = await http.post(
        Uri.parse('$baseUrl/generate-discoverable-auth-options'),
      );

      // Pass the PIN into the channel
      final String resultJson = await _channel.invokeMethod('authenticate', {
        'options': optionsRes.body,
        'pin': pin,
      });

      // We do NOT send a username back to the server! The Yubikey provides it in response_data.
      final payload = {"response_data": jsonDecode(resultJson)};

      final verifyRes = await http.post(
        Uri.parse('$baseUrl/verify-authentication'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode(payload),
      );

      if (verifyRes.statusCode != 200) throw Exception("Server rejected login");

      final serverResponse = jsonDecode(verifyRes.body);
      print("🔓 ${serverResponse['message']}");

      return serverResponse['message'];
    } catch (e) {
      print("❌ Native Login Error: $e");
      rethrow;
    }
  }
}
