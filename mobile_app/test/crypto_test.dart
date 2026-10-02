import 'package:flutter_test/flutter_test.dart';
import 'package:secure_messenger/services/crypto_service.dart';

void main() {
  final c = CryptoService();

  test('Dart <-> Dart round trip', () async {
    final bob = await c.generateIdentity();
    final env = await c.encrypt(
        from: 'alice', to: 'bob', id: 'm1', text: 'hello secure world',
        expiresAt: 0, recipientPublicKey: bob.publicKey);
    final text = await c.decrypt(
        env: env, myPrivateKey: bob.privateKey, myPublicKey: bob.publicKey);
    expect(text, 'hello secure world');
  });

  test('wrong key cannot decrypt', () async {
    final bob = await c.generateIdentity();
    final eve = await c.generateIdentity();
    final env = await c.encrypt(
        from: 'alice', to: 'bob', id: 'm2', text: 'secret',
        expiresAt: 0, recipientPublicKey: bob.publicKey);
    expect(
        () => c.decrypt(env: env, myPrivateKey: eve.privateKey, myPublicKey: eve.publicKey),
        throwsA(anything));
  });

  test('tampered ciphertext is rejected', () async {
    final bob = await c.generateIdentity();
    final env = await c.encrypt(
        from: 'alice', to: 'bob', id: 'm3', text: 'secret',
        expiresAt: 0, recipientPublicKey: bob.publicKey);
    env['from'] = 'mallory'; // AAD binding catches spoofed sender
    expect(
        () => c.decrypt(env: env, myPrivateKey: bob.privateKey, myPublicKey: bob.publicKey),
        throwsA(anything));
  });

  // Envelope produced by server/test/e2ee.js (Node.js) -> proves both sides interoperate.
  test('decrypts an envelope created by the Node.js reference implementation', () async {
    final env = <String, dynamic>{
      'id': 'fixture1', 'from': 'alice', 'to': 'bob',
      'cp': 'mSyb1q7iiIyX7HuaDt13Hu+uplo=',
      'ta': 'Tme5P8f7tDE1x3v9pei+iA==',
      'nonce': 'ODMVC6p/OjPIRKXV',
      'expiresAt': 0,
      'ck': {
        'epk': 'T7LDgX9l+xE7zn47W2oRH3g8kUSstC0xgxxZ8bWmCSA=',
        'nonce': '8MZHU8oweJ4RPdYJ',
        'ct': 'WI5vWY4HbpV8eDfmP+7FXJF3fPueL9akoile67WZf9M=',
        'tag': 'XvIG62zf/sdxhpGWo4V2zA==',
      },
    };
    final text = await c.decrypt(
        env: env, myPrivateKey: 'eAT1aZx5/inELSQ1t3m3Xnp3Ymvk0nrnmuoAbf0DjXI=', myPublicKey: '9xkY5OYEz+zyRoGV1CZqnsyZ9qCZcv4h7w7DEJceEDU=');
    expect(text, 'Hello from Node 🔐');
  });
}
