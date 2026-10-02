import 'package:flutter/material.dart';
import '../app_state.dart';
import 'chat_screen.dart';

class ContactsScreen extends StatefulWidget {
  const ContactsScreen({super.key});
  @override
  State<ContactsScreen> createState() => _ContactsScreenState();
}

class _ContactsScreenState extends State<ContactsScreen> {
  final _search = TextEditingController();
  List<Map<String, dynamic>> _results = [];
  String? _error;

  @override
  void initState() {
    super.initState();
    _load('');
  }

  Future<void> _load(String q) async {
    try {
      final r = await AppState.instance.api!.searchUsers(q.trim().toLowerCase());
      if (mounted) setState(() { _results = r; _error = null; });
    } catch (e) {
      if (mounted) setState(() => _error = e.toString());
    }
  }

  @override
  Widget build(BuildContext context) {
    final app = AppState.instance;
    return ListenableBuilder(
      listenable: app,
      builder: (_, __) {
        // people with existing chats first, then directory results
        final names = {...app.chats.keys, ..._results.map((e) => e['username'] as String)}.toList();
        return Scaffold(
          appBar: AppBar(
            title: Text('@${app.username}'),
            actions: [
              Icon(app.connected ? Icons.cloud_done : Icons.cloud_off,
                  color: app.connected ? Colors.green : Colors.red),
              IconButton(
                  tooltip: 'Log out (wipes chats from memory)',
                  onPressed: app.logout,
                  icon: const Icon(Icons.logout)),
            ],
          ),
          body: Column(
            children: [
              Padding(
                padding: const EdgeInsets.all(12),
                child: TextField(
                  controller: _search,
                  onChanged: _load,
                  decoration: const InputDecoration(
                      prefixIcon: Icon(Icons.search),
                      hintText: 'Find a user by username',
                      border: OutlineInputBorder()),
                ),
              ),
              if (_error != null) Text(_error!, style: const TextStyle(color: Colors.red)),
              Expanded(
                child: ListView(
                  children: [
                    for (final n in names)
                      ListTile(
                        leading: Stack(children: [
                          CircleAvatar(child: Text(n[0].toUpperCase())),
                          Positioned(
                            right: 0,
                            bottom: 0,
                            child: CircleAvatar(
                                radius: 6,
                                backgroundColor:
                                    app.online[n] == true || (_results.any((e) => e['username'] == n && e['online'] == true))
                                        ? Colors.green
                                        : Colors.grey),
                          ),
                        ]),
                        title: Text(n),
                        subtitle: Text(app.chats[n]?.isNotEmpty == true
                            ? '🔒 ${app.chats[n]!.length} message(s)'
                            : 'Tap to start a secure chat'),
                        onTap: () => Navigator.push(
                            context, MaterialPageRoute(builder: (_) => ChatScreen(peer: n))),
                      ),
                    if (names.isEmpty)
                      const Padding(
                          padding: EdgeInsets.all(32),
                          child: Center(child: Text('No other users yet. Register a second account to chat.'))),
                  ],
                ),
              ),
            ],
          ),
        );
      },
    );
  }
}
