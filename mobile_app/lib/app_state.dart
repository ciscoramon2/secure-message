import 'dart:async';
import 'dart:math';
import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:socket_io_client/socket_io_client.dart' as io;
import 'services/api_service.dart';
import 'services/crypto_service.dart';

class ChatMessage {
  final String id;
  final String peer;
  final bool mine;
  String text;
  final DateTime sentAt;
  final int expiresAt; // epoch ms, 0 = never
  String status; // sending | sent | queued | delivered | read
  ChatMessage(this.id, this.peer, this.mine, this.text, this.sentAt, this.expiresAt,
      [this.status = 'sending']);
}

/// Central app state: auth, keys, socket, in-memory (ephemeral) message store.
/// Plaintext lives only in RAM and is wiped when a message expires.
class AppState extends ChangeNotifier {
  static final AppState instance = AppState._();
  AppState._();

  final _crypto = CryptoService();
  final _storage = const FlutterSecureStorage();
  final _rng = Random.secure();

  ApiService? api;
  io.Socket? _socket;
  String? username;
  String? _myPriv;
  String? _myPub;
  bool connected = false;

  final Map<String, List<ChatMessage>> chats = {};
  final Map<String, bool> online = {};
  final Map<String, DateTime> typingAt = {};
  final Map<String, String> _keyCache = {};
  final Map<String, Timer> _timers = {};

  bool get loggedIn => username != null;

  String _newId() =>
      List.generate(16, (_) => _rng.nextInt(256).toRadixString(16).padLeft(2, '0')).join();

  // ---------- auth ----------
  Future<void> register(String server, String user, String pass) async {
    api = ApiService(server);
    final id = await _crypto.generateIdentity(); // keys are born on the device
    final res = await api!.register(user, pass, id.publicKey);
    final u = res['username'] as String;
    await _storage.write(key: 'priv_$u', value: id.privateKey);
    await _storage.write(key: 'pub_$u', value: id.publicKey);
    await _start(u, res['token'], id.privateKey, id.publicKey);
  }

  Future<void> login(String server, String user, String pass) async {
    api = ApiService(server);
    final res = await api!.login(user, pass);
    final u = res['username'] as String;
    final priv = await _storage.read(key: 'priv_$u');
    final pub = await _storage.read(key: 'pub_$u');
    if (priv == null || pub == null || pub != res['publicKey']) {
      throw ApiException(
          'No private key for "$u" on this device. Keys never leave the device where the account was created.');
    }
    await _start(u, res['token'], priv, pub);
  }

  Future<void> _start(String u, String token, String priv, String pub) async {
    api!.token = token;
    username = u;
    _myPriv = priv;
    _myPub = pub;
    _connectSocket(token);
    notifyListeners();
  }

  Future<void> logout() async {
    _socket?.dispose();
    _socket = null;
    for (final t in _timers.values) {
      t.cancel();
    }
    _timers.clear();
    chats.clear(); // plaintext wiped from memory
    online.clear();
    _keyCache.clear();
    username = null;
    _myPriv = null;
    _myPub = null;
    connected = false;
    notifyListeners();
  }

  // ---------- socket ----------
  void _connectSocket(String token) {
    final s = io.io(
      api!.baseUrl,
      io.OptionBuilder()
          .setTransports(['websocket'])
          .setAuth({'token': token})
          .enableReconnection() // exponential-backoff style reconnects
          .setReconnectionDelay(1000)
          .setReconnectionDelayMax(15000)
          .disableAutoConnect()
          .build(),
    );
    s.onConnect((_) {
      connected = true;
      notifyListeners();
    });
    s.onDisconnect((_) {
      connected = false;
      notifyListeners();
    });
    s.on('presence', (d) {
      online[d['username']] = d['online'] == true;
      notifyListeners();
    });
    s.on('message', (d) => _onIncoming(Map<String, dynamic>.from(d)));
    s.on('receipt', (d) => _setStatus(d['from'], d['id'], d['type']));
    s.on('burn', (d) => _remove(d['from'], d['id']));
    s.on('typing', (d) {
      typingAt[d['from']] = DateTime.now();
      notifyListeners();
    });
    s.connect();
    _socket = s;
  }

  Future<void> _onIncoming(Map<String, dynamic> env) async {
    try {
      final text = await _crypto.decrypt(
          env: env, myPrivateKey: _myPriv!, myPublicKey: _myPub!);
      final exp = (env['expiresAt'] as num).toInt();
      if (exp != 0 && exp <= DateTime.now().millisecondsSinceEpoch) return;
      final m = ChatMessage(env['id'], env['from'], false, text,
          DateTime.fromMillisecondsSinceEpoch((env['sentAt'] as num).toInt()), exp, 'delivered');
      _add(m);
      _socket?.emit('receipt', {'to': m.peer, 'id': m.id, 'type': 'delivered'});
    } catch (_) {
      // authentication tag failed -> silently discard (integrity guarantee)
    }
  }

  // ---------- messaging ----------
  Future<void> send(String peer, String text, int ttlSeconds) async {
    if (text.trim().isEmpty) return;
    final id = _newId();
    final now = DateTime.now();
    final exp = ttlSeconds > 0 ? now.millisecondsSinceEpoch + ttlSeconds * 1000 : 0;
    final m = ChatMessage(id, peer, true, text.trim(), now, exp);
    _add(m);
    try {
      final key = _keyCache[peer] ??= await api!.publicKeyOf(peer);
      final env = await _crypto.encrypt(
          from: username!, to: peer, id: id, text: m.text, expiresAt: exp, recipientPublicKey: key);
      _socket!.emitWithAck('send', env, ack: (res) {
        final ok = res is Map && res['ok'] == true;
        m.status = !ok ? 'failed' : (res['delivered'] == true ? 'sent' : 'queued');
        notifyListeners();
      });
    } catch (_) {
      m.status = 'failed';
      notifyListeners();
    }
  }

  void sendTyping(String peer) => _socket?.emit('typing', {'to': peer});

  void markRead(String peer) {
    for (final m in chats[peer] ?? <ChatMessage>[]) {
      if (!m.mine && m.status != 'read') {
        m.status = 'read';
        _socket?.emit('receipt', {'to': peer, 'id': m.id, 'type': 'read'});
      }
    }
  }

  /// Delete a message on both devices immediately.
  void burn(String peer, String id) {
    _socket?.emit('burn', {'to': peer, 'id': id});
    _remove(peer, id);
  }

  // ---------- ephemeral store ----------
  void _add(ChatMessage m) {
    chats.putIfAbsent(m.peer, () => []).add(m);
    if (m.expiresAt != 0) {
      final ms = m.expiresAt - DateTime.now().millisecondsSinceEpoch;
      _timers[m.id] = Timer(Duration(milliseconds: max(0, ms)), () => _remove(m.peer, m.id));
    }
    notifyListeners();
  }

  void _remove(String peer, String id) {
    _timers.remove(id)?.cancel();
    final list = chats[peer];
    if (list == null) return;
    for (final m in list.where((m) => m.id == id)) {
      m.text = ''; // drop plaintext reference before removal
    }
    list.removeWhere((m) => m.id == id);
    notifyListeners();
  }

  void _setStatus(String peer, String id, String type) {
    for (final m in chats[peer] ?? <ChatMessage>[]) {
      if (m.id == id && m.mine) m.status = type;
    }
    notifyListeners();
  }
}
