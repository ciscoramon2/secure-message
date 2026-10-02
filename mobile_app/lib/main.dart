import 'package:flutter/material.dart';
import 'app_state.dart';
import 'screens/contacts_screen.dart';
import 'screens/login_screen.dart';

void main() => runApp(const SecureMessengerApp());

class SecureMessengerApp extends StatelessWidget {
  const SecureMessengerApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Secure Messenger',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorSchemeSeed: const Color(0xFF0B6E4F),
        useMaterial3: true,
      ),
      home: ListenableBuilder(
        listenable: AppState.instance,
        builder: (_, __) =>
            AppState.instance.loggedIn ? const ContactsScreen() : const LoginScreen(),
      ),
    );
  }
}
