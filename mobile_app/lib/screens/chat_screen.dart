import 'dart:async';
import 'package:flutter/material.dart';
import '../app_state.dart';

class ChatScreen extends StatefulWidget {
  final String peer;
  const ChatScreen({super.key, required this.peer});
  @override
  State<ChatScreen> createState() => _ChatScreenState();
}

class _ChatScreenState extends State<ChatScreen> {
  final _ctrl = TextEditingController();
  final _scroll = ScrollController();
  Timer? _tick;
  int _ttl = 0; // seconds, 0 = off
  DateTime _lastTyping = DateTime.fromMillisecondsSinceEpoch(0);
  static const _options = {0: 'Off', 30: '30 sec', 300: '5 min', 3600: '1 hour'};

  @override
  void initState() {
    super.initState();
    // 1s tick refreshes the self-destruct countdowns
    _tick = Timer.periodic(const Duration(seconds: 1), (_) {
      if (mounted) setState(() {});
    });
  }

  @override
  void dispose() {
    _tick?.cancel();
    super.dispose();
  }

  String _countdown(int exp) {
    final s = ((exp - DateTime.now().millisecondsSinceEpoch) / 1000).ceil();
    if (s <= 0) return '0s';
    if (s >= 3600) return '${(s / 3600).floor()}h';
    if (s >= 60) return '${(s / 60).floor()}m ${s % 60}s';
    return '${s}s';
  }

  IconData _statusIcon(String s) => switch (s) {
        'sending' => Icons.schedule,
        'queued' => Icons.cloud_queue,
        'sent' => Icons.check,
        'delivered' => Icons.done_all,
        'read' => Icons.done_all,
        _ => Icons.error_outline,
      };

  void _send() {
    final t = _ctrl.text;
    if (t.trim().isEmpty) return;
    AppState.instance.send(widget.peer, t, _ttl);
    _ctrl.clear();
    Future.delayed(const Duration(milliseconds: 100), () {
      if (_scroll.hasClients) _scroll.jumpTo(_scroll.position.maxScrollExtent);
    });
  }

  @override
  Widget build(BuildContext context) {
    final app = AppState.instance;
    return ListenableBuilder(
      listenable: app,
      builder: (_, __) {
        app.markRead(widget.peer);
        final msgs = app.chats[widget.peer] ?? [];
        final typing = app.typingAt[widget.peer] != null &&
            DateTime.now().difference(app.typingAt[widget.peer]!) < const Duration(seconds: 3);
        return Scaffold(
          appBar: AppBar(
            title: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text(widget.peer),
              Text(typing ? 'typing…' : (app.online[widget.peer] == true ? 'online' : 'offline'),
                  style: const TextStyle(fontSize: 12)),
            ]),
            actions: [
              PopupMenuButton<int>(
                tooltip: 'Self-destruct timer',
                icon: Icon(_ttl == 0 ? Icons.timer_off_outlined : Icons.timer),
                onSelected: (v) => setState(() => _ttl = v),
                itemBuilder: (_) => [
                  for (final e in _options.entries)
                    CheckedPopupMenuItem(value: e.key, checked: _ttl == e.key, child: Text(e.value)),
                ],
              ),
            ],
          ),
          body: Column(children: [
            Container(
              width: double.infinity,
              color: Colors.green.withOpacity(0.1),
              padding: const EdgeInsets.all(6),
              child: const Text('🔒 End-to-end encrypted. The server cannot read these messages.',
                  textAlign: TextAlign.center, style: TextStyle(fontSize: 12)),
            ),
            Expanded(
              child: ListView.builder(
                controller: _scroll,
                padding: const EdgeInsets.all(12),
                itemCount: msgs.length,
                itemBuilder: (_, i) {
                  final m = msgs[i];
                  return Align(
                    alignment: m.mine ? Alignment.centerRight : Alignment.centerLeft,
                    child: GestureDetector(
                      onLongPress: () => showDialog(
                        context: context,
                        builder: (ctx) => AlertDialog(
                          title: const Text('Delete for both?'),
                          content: const Text('This message will be destroyed on both devices.'),
                          actions: [
                            TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('Cancel')),
                            TextButton(
                                onPressed: () {
                                  app.burn(widget.peer, m.id);
                                  Navigator.pop(ctx);
                                },
                                child: const Text('Delete')),
                          ],
                        ),
                      ),
                      child: Container(
                        margin: const EdgeInsets.symmetric(vertical: 3),
                        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                        constraints: BoxConstraints(maxWidth: MediaQuery.of(context).size.width * 0.78),
                        decoration: BoxDecoration(
                          color: m.mine
                              ? Theme.of(context).colorScheme.primaryContainer
                              : Theme.of(context).colorScheme.surfaceContainerHighest,
                          borderRadius: BorderRadius.circular(14),
                        ),
                        child: Column(crossAxisAlignment: CrossAxisAlignment.end, children: [
                          Align(alignment: Alignment.centerLeft, child: Text(m.text)),
                          const SizedBox(height: 2),
                          Row(mainAxisSize: MainAxisSize.min, children: [
                            if (m.expiresAt != 0) ...[
                              const Icon(Icons.local_fire_department, size: 12, color: Colors.orange),
                              Text(' ${_countdown(m.expiresAt)}  ', style: const TextStyle(fontSize: 10)),
                            ],
                            if (m.mine)
                              Icon(_statusIcon(m.status),
                                  size: 14, color: m.status == 'read' ? Colors.blue : Colors.grey),
                          ]),
                        ]),
                      ),
                    ),
                  );
                },
              ),
            ),
            SafeArea(
              child: Padding(
                padding: const EdgeInsets.fromLTRB(8, 4, 8, 8),
                child: Row(children: [
                  Expanded(
                    child: TextField(
                      controller: _ctrl,
                      minLines: 1,
                      maxLines: 4,
                      onChanged: (_) {
                        if (DateTime.now().difference(_lastTyping) > const Duration(seconds: 2)) {
                          _lastTyping = DateTime.now();
                          app.sendTyping(widget.peer);
                        }
                      },
                      onSubmitted: (_) => _send(),
                      decoration: InputDecoration(
                        hintText: _ttl == 0 ? 'Message' : 'Message (disappears in ${_options[_ttl]})',
                        border: const OutlineInputBorder(borderRadius: BorderRadius.all(Radius.circular(24))),
                        contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
                      ),
                    ),
                  ),
                  const SizedBox(width: 6),
                  IconButton.filled(onPressed: _send, icon: const Icon(Icons.send)),
                ]),
              ),
            ),
          ]),
        );
      },
    );
  }
}
