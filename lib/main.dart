import 'package:flutter/material.dart';
import 'auth_service.dart';
import 'package:flutter_dotenv/flutter_dotenv.dart';

Future<void> main() async {
  await dotenv.load(fileName: ".env");
  runApp(const MaterialApp(home: WebAuthnTestPage()));
}

class WebAuthnTestPage extends StatefulWidget {
  const WebAuthnTestPage({super.key});

  @override
  State<WebAuthnTestPage> createState() => _WebAuthnTestPageState();
}

class _WebAuthnTestPageState extends State<WebAuthnTestPage> {
  final AuthService _authService = AuthService();
  final TextEditingController _controller = TextEditingController(
    text: "test_user",
  );
  String _status = "Ready";

  // --- REGISTRATION ---
  void _handleFetchChallenge() async {
    setState(() => _status = "Starting Native Registration...");
    try {
      // The new AuthService handles everything in one call!
      await _authService.registerYubikey(_controller.text);

      setState(() => _status = "✅ YubiKey Verified & Saved in DB!");
    } catch (e) {
      setState(() => _status = "Error: $e");
    }
  }

  // --- LOGIN ---
  void _handleLogin() async {
    setState(() => _status = "Starting Native Login...");
    try {
      // The new AuthService handles everything in one call!
      await _authService.loginYubikey(_controller.text);

      setState(() => _status = "🔓 Successfully Logged In!");
    } catch (e) {
      setState(() => _status = "Login Error: $e");
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text("FIDO2/WebAuthn Test")),
      body: Padding(
        padding: const EdgeInsets.all(20.0),
        child: Column(
          children: [
            TextField(
              controller: _controller,
              decoration: const InputDecoration(labelText: "Username"),
            ),
            const SizedBox(height: 20),
            ElevatedButton(
              onPressed: _handleFetchChallenge,
              child: const Text("1. Register YubiKey"),
            ),
            const SizedBox(height: 10),
            ElevatedButton(
              onPressed: _handleLogin,
              child: const Text("2. Login with YubiKey"),
            ),
            const SizedBox(height: 20),
            Text(
              "Status: $_status",
              style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 16),
              textAlign: TextAlign.center,
            ),
          ],
        ),
      ),
    );
  }
}
