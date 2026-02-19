import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:flutter/services.dart'; // Needed for MethodChannel
import 'package:flutter_dotenv/flutter_dotenv.dart';

class AuthService {
  static String baseUrl = dotenv.env['API_BASE_URL'] ?? 'http://10.0.2.2:8000';

  // Connects to our custom Kotlin bridge
  static const MethodChannel _channel = MethodChannel(
    'com.example.lip_app/fido',
  );

  // ==========================================
  // 1. REGISTRATION
  // ==========================================
  Future<void> registerYubikey(String username) async {
    try {
      print("Starting Native Registration...");
      final optionsRes = await http.post(
        Uri.parse('$baseUrl/generate-registration-options?username=$username'),
      );
      if (optionsRes.statusCode != 200) {
        throw Exception('Failed to get options from server');
      }

      // --- THE INTERCEPTOR: Inject FIDO2 Native Rules ---
      final Map<String, dynamic> decoded = jsonDecode(optionsRes.body);

      if (decoded['user'] != null) {
        decoded['user']['displayName'] ??= decoded['user']['name'] ?? 'User';
      }

      decoded['authenticatorSelection'] = {
        'authenticatorAttachment': 'cross-platform',
        'requireResidentKey': false, // Matches your FIDO2-only hardware config
        'residentKey': 'discouraged', // Matches your FIDO2-only hardware config
      };

      decoded['attestation'] = 'none';
      decoded['excludeCredentials'] ??= [];

      // Re-encode to send to Kotlin
      final String modifiedOptionsJson = jsonEncode(decoded);
      // --------------------------------------------------

      // Call Native Kotlin with the strictly modified JSON
      final String resultJson = await _channel.invokeMethod('register', {
        'options': modifiedOptionsJson,
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
      print("✅ Native Registration Success!");
    } catch (e) {
      print("❌ Native Registration Error: $e");
      rethrow;
    }
  }

  // ==========================================
  // 2. LOGIN (AUTHENTICATION)
  // ==========================================
  Future<void> loginYubikey(String username) async {
    try {
      print("Starting Native Login...");
      final optionsRes = await http.post(
        Uri.parse(
          '$baseUrl/generate-authentication-options?username=$username',
        ),
      );
      if (optionsRes.statusCode != 200) {
        throw Exception('Failed to get auth options');
      }

      // Call Native Kotlin
      final String resultJson = await _channel.invokeMethod('authenticate', {
        'options': optionsRes.body,
      });

      final payload = {
        "username": username,
        "response_data": jsonDecode(resultJson),
      };

      final verifyRes = await http.post(
        Uri.parse('$baseUrl/verify-authentication'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode(payload),
      );

      if (verifyRes.statusCode != 200) throw Exception("Server rejected login");
      print("🔓 Native Login Success!");
    } catch (e) {
      print("❌ Native Login Error: $e");
      rethrow;
    }
  }
}
