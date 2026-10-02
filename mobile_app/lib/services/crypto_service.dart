import 'dart:convert';
import 'package:cryptography/cryptography.dart';

/// Hybrid E2EE engine:
///   payload  -> AES-256-GCM with a fresh random session key Ks (gives Cp + Ta)
///   Ks       -> wrapped for the recipient with an ephemeral X25519 (ECC) key
///               agreement + HKDF-SHA256 + AES-256-GCM (gives Ck)
/// Wire format is identical to server/test/e2ee.js.
class CryptoService {
  static final _x25519 = X25519();
  static final _aes = AesGcm.with256bits();
  static final _hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);
  static final _info = utf8.encode('e2ee-key-wrap-v1');
  static final _wrapAad = utf8.encode('wrap');

  /// Generates the long-term identity key pair (base64 strings, 32 bytes each).
  Future<({String publicKey, String privateKey})> generateIdentity() async {
    final kp = await _x25519.newKeyPair();
    final pub = await kp.extractPublicKey();
    final priv = await kp.extractPrivateKeyBytes();
    return (publicKey: base64Encode(pub.bytes), privateKey: base64Encode(priv));
  }

  SimplePublicKey _pub(String b64) =>
      SimplePublicKey(base64Decode(b64), type: KeyPairType.x25519);

  SimpleKeyPairData _pair(String privB64, String pubB64) => SimpleKeyPairData(
        base64Decode(privB64),
        publicKey: _pub(pubB64),
        type: KeyPairType.x25519,
      );

  Future<SecretKey> _kek(KeyPair mine, SimplePublicKey theirs) async {
    final shared =
        await _x25519.sharedSecretKey(keyPair: mine, remotePublicKey: theirs);
    return _hkdf.deriveKey(secretKey: shared, nonce: const <int>[], info: _info);
  }

  List<int> _aad(String from, String to, String id, int exp) =>
      utf8.encode('$from|$to|$id|$exp');

  /// Builds the encrypted envelope {cp, ta, nonce, ck} for the recipient.
  Future<Map<String, dynamic>> encrypt({
    required String from,
    required String to,
    required String id,
    required String text,
    required int expiresAt,
    required String recipientPublicKey,
  }) async {
    final ks = await _aes.newSecretKey(); // CSPRNG 256-bit session key
    final ksBytes = await ks.extractBytes();
    final box = await _aes.encrypt(
      utf8.encode(text),
      secretKey: ks,
      aad: _aad(from, to, id, expiresAt),
    );

    final eph = await _x25519.newKeyPair();
    final ephPub = await eph.extractPublicKey();
    final kek = await _kek(eph, _pub(recipientPublicKey));
    final wrap = await _aes.encrypt(ksBytes, secretKey: kek, aad: _wrapAad);

    // best-effort wipe of the raw session key bytes
    for (var i = 0; i < ksBytes.length; i++) {
      ksBytes[i] = 0;
    }

    return {
      'id': id,
      'from': from,
      'to': to,
      'cp': base64Encode(box.cipherText),
      'ta': base64Encode(box.mac.bytes),
      'nonce': base64Encode(box.nonce),
      'expiresAt': expiresAt,
      'ck': {
        'epk': base64Encode(ephPub.bytes),
        'nonce': base64Encode(wrap.nonce),
        'ct': base64Encode(wrap.cipherText),
        'tag': base64Encode(wrap.mac.bytes),
      },
    };
  }

  /// Decrypts an envelope. Throws if the auth tag does not verify
  /// (tampering, wrong key, spoofed sender).
  Future<String> decrypt({
    required Map<String, dynamic> env,
    required String myPrivateKey,
    required String myPublicKey,
  }) async {
    final ck = Map<String, dynamic>.from(env['ck'] as Map);
    final kek = await _kek(_pair(myPrivateKey, myPublicKey), _pub(ck['epk']));
    final ksBytes = await _aes.decrypt(
      SecretBox(base64Decode(ck['ct']),
          nonce: base64Decode(ck['nonce']), mac: Mac(base64Decode(ck['tag']))),
      secretKey: kek,
      aad: _wrapAad,
    );
    final plain = await _aes.decrypt(
      SecretBox(base64Decode(env['cp']),
          nonce: base64Decode(env['nonce']), mac: Mac(base64Decode(env['ta']))),
      secretKey: SecretKey(ksBytes),
      aad: _aad(env['from'], env['to'], env['id'], (env['expiresAt'] as num).toInt()),
    );
    for (var i = 0; i < ksBytes.length; i++) {
      ksBytes[i] = 0;
    }
    return utf8.decode(plain);
  }
}
