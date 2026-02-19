import 'package:flutter/material.dart';
import 'package:flutter_dotenv/flutter_dotenv.dart';
import 'auth_service.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
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
  final TextEditingController _userController = TextEditingController(
    text: "boss_user",
  );
  final TextEditingController _pinController = TextEditingController();
  String _status = "Ready";

  void _handleRegister() async {
    if (_pinController.text.isEmpty) {
      setState(() => _status = "Please enter your YubiKey PIN first.");
      return;
    }
    setState(() => _status = "Registering Resident Key to YubiKey...");
    try {
      await _authService.registerYubikey(
        _userController.text,
        _pinController.text,
      );
      setState(() => _status = "✅ Resident Key Saved INSIDE YubiKey!");
    } catch (e) {
      setState(() => _status = "Error: $e");
    }
  }

  void _handleLogin() async {
    if (_pinController.text.isEmpty) {
      setState(() => _status = "Please enter your YubiKey PIN first.");
      return;
    }
    setState(() => _status = "Tap YubiKey to Login (No Username Needed!)...");
    try {
      String welcomeMessage = await _authService.loginDiscoverable(
        _pinController.text,
      );
      setState(() => _status = "🔓 $welcomeMessage");
    } catch (e) {
      setState(() => _status = "Login Error: $e");
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text("True Passwordless Test")),
      body: Padding(
        padding: const EdgeInsets.all(20.0),
        child: Column(
          children: [
            TextField(
              controller: _userController,
              decoration: const InputDecoration(
                labelText: "Create an Account Name",
              ),
            ),
            const SizedBox(height: 10),
            TextField(
              controller: _pinController,
              decoration: const InputDecoration(labelText: "YubiKey PIN"),
              obscureText: true,
              keyboardType: TextInputType.number,
            ),
            const SizedBox(height: 20),
            ElevatedButton(
              onPressed: _handleRegister,
              child: const Text("1. Register Account TO YubiKey"),
            ),
            const Divider(height: 50, thickness: 2),
            const Text(
              "Later, when you return to the app:",
              style: TextStyle(fontStyle: FontStyle.italic),
            ),
            const SizedBox(height: 10),
            ElevatedButton(
              style: ElevatedButton.styleFrom(
                backgroundColor: Colors.green,
                foregroundColor: Colors.white,
                padding: const EdgeInsets.all(15),
              ),
              onPressed: _handleLogin,
              child: const Text("2. Login (PIN + YubiKey Only)"),
            ),
            const SizedBox(height: 30),
            Text(
              "Status:\n$_status",
              style: const TextStyle(
                fontWeight: FontWeight.bold,
                fontSize: 16,
                color: Colors.blue,
              ),
              textAlign: TextAlign.center,
            ),
          ],
        ),
      ),
    );
  }
}
