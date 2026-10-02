import 'package:flutter/material.dart';
import '../app_state.dart';

class LoginScreen extends StatefulWidget {
  const LoginScreen({super.key});
  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen> {
  // 10.0.2.2 = host machine as seen from the Android emulator.
  // On a real phone use your PC's LAN IP, e.g. http://192.168.1.10:3000
  final _server = TextEditingController(text: 'http://10.0.2.2:3000');
  final _user = TextEditingController();
  final _pass = TextEditingController();
  bool _register = false;
  bool _busy = false;
  String? _error;

  Future<void> _submit() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final s = _server.text.trim().replaceAll(RegExp(r'/+$'), '');
      final u = _user.text.trim().toLowerCase();
      if (_register) {
        await AppState.instance.register(s, u, _pass.text);
      } else {
        await AppState.instance.login(s, u, _pass.text);
      }
    } catch (e) {
      setState(() => _error = e.toString());
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(24),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 420),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Icon(Icons.lock_rounded, size: 64, color: Theme.of(context).colorScheme.primary),
                  const SizedBox(height: 8),
                  Text('Secure Messenger',
                      textAlign: TextAlign.center,
                      style: Theme.of(context).textTheme.headlineMedium),
                  const Text('End-to-end encrypted • self-destructing messages',
                      textAlign: TextAlign.center),
                  const SizedBox(height: 24),
                  TextField(
                      controller: _server,
                      keyboardType: TextInputType.url,
                      decoration: const InputDecoration(
                          labelText: 'Server URL', border: OutlineInputBorder())),
                  const SizedBox(height: 12),
                  TextField(
                      controller: _user,
                      autocorrect: false,
                      decoration: const InputDecoration(
                          labelText: 'Username', border: OutlineInputBorder())),
                  const SizedBox(height: 12),
                  TextField(
                      controller: _pass,
                      obscureText: true,
                      decoration: const InputDecoration(
                          labelText: 'Password', border: OutlineInputBorder())),
                  if (_error != null)
                    Padding(
                      padding: const EdgeInsets.only(top: 12),
                      child: Text(_error!, style: const TextStyle(color: Colors.red)),
                    ),
                  const SizedBox(height: 16),
                  FilledButton(
                    onPressed: _busy ? null : _submit,
                    child: _busy
                        ? const SizedBox(
                            height: 20, width: 20, child: CircularProgressIndicator(strokeWidth: 2))
                        : Text(_register ? 'Create account' : 'Log in'),
                  ),
                  TextButton(
                    onPressed: _busy ? null : () => setState(() => _register = !_register),
                    child: Text(_register
                        ? 'I already have an account'
                        : 'New here? Create account (generates your encryption keys)'),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}
