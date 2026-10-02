# Secure Text-Messaging Application Using End-to-End Encryption

KWASU final-year project implementation: Flutter mobile client + Node.js/Socket.io zero-knowledge relay server.

```
secure-messenger/
├── server/          Node.js + Express + Socket.io relay (tested, 15 automated checks)
│   ├── server.js
│   └── test/        e2ee.js (reference crypto) + e2e.test.js (end-to-end tests + latency benchmark)
└── mobile_app/      Flutter (Dart) client
    ├── lib/services/crypto_service.dart   AES-256-GCM + X25519 hybrid engine
    ├── lib/app_state.dart                 keys, socket, ephemeral message store
    ├── lib/screens/                       login, contacts, chat UI
    └── test/crypto_test.dart              unit tests incl. Node<->Dart interop vector
```

## How the encryption works (matches Section 2.2.3 of your report)

1. Account creation: the phone generates an X25519 (ECC) key pair. Public key goes to the server; private key stays in Android Keystore / iOS Keychain (`flutter_secure_storage`).
2. Sending: random 256-bit session key **Ks** -> AES-256-GCM encrypts the text -> **Cp** + 128-bit tag **Ta**.
3. **Ks** is wrapped for the recipient: ephemeral X25519 key agreement with their public key -> HKDF-SHA256 -> AES-GCM -> **Ck**.
4. Packet `{Cp, Ta, nonce, Ck}` goes over Socket.io. Sender, recipient and expiry time are bound into the GCM associated data, so tampering or spoofing makes decryption fail.
5. Recipient unwraps **Ks** with their private key, verifies **Ta**, decrypts, then Ks is zeroed.
6. Self-destruct: each message has an expiry; timers delete it from RAM on both phones, and the server purges expired queued packets. Long-press a message to delete it on both devices instantly.

---

## 1. Run the server

Requires Node.js 18+ (https://nodejs.org).

```bash
cd server
npm install
npm start            # listens on http://0.0.0.0:3000
```

Check: open http://localhost:3000/health -> `{"ok":true}`

Run the automated tests (screenshots of this output are good for Chapter 4):

```bash
npm test
```

Optional: `JWT_SECRET=your-long-random-string npm start` (set a real secret for anything beyond a demo).

## 2. Run the mobile app

Requires Flutter SDK 3.19+ (https://docs.flutter.dev/get-started/install) and Android Studio (emulator) or a phone with USB debugging.

```bash
cd mobile_app
flutter create --org edu.kwasu --project-name secure_messenger .
flutter pub get
```

(`flutter create .` generates the android/ and ios/ folders around the existing code. It will not overwrite `lib/` or `pubspec.yaml`. Then delete the auto-generated `test/widget_test.dart`.)

**Allow plain HTTP for local testing** - open `android/app/src/main/AndroidManifest.xml` and add one attribute to the `<application` tag:

```xml
<application
    android:usesCleartextTraffic="true"
    ... >
```

**flutter_secure_storage needs minSdk 23**: in `android/app/build.gradle` (or `build.gradle.kts`) set `minSdk = 23` (or `minSdkVersion 23`).

Run:

```bash
flutter test         # crypto unit tests + Node interop test
flutter run
```

### Server URL on the login screen

| Where the app runs | Server URL |
|---|---|
| Android emulator | `http://10.0.2.2:3000` (default) |
| Real phone, same Wi-Fi as PC | `http://<PC-LAN-IP>:3000` (find it with `ipconfig` / `ifconfig`); allow port 3000 in the PC firewall |

## 3. Demo script for your defence

1. Start the server (keep its terminal visible - it logs no message content).
2. Run the app on two devices (two emulators, or emulator + phone). Create accounts `alice` and `bob`.
3. From alice, open `bob`, send messages. Show delivery ticks, typing indicator, online/offline status.
4. Set the timer (top-right) to 30 sec and send - watch the fire countdown, then the message vanishes on both phones.
5. Kill bob's app, send from alice (cloud icon = queued), reopen bob - message arrives and decrypts.
6. Show the server's `users.json`: only usernames, bcrypt hashes, public keys - no messages.
7. Run `npm test` live to show tamper detection, wrong-key failure, expiry purge and latency numbers.

## 4. Mapping to your objectives

| Objective | Where |
|---|---|
| Zero-knowledge architecture with WebSockets | `server/server.js` |
| Hybrid AES-256-GCM + ECC key distribution | `crypto_service.dart`, `test/e2ee.js` |
| Flutter mobile client | `mobile_app/lib` |
| Ephemeral message engine | `app_state.dart` (`_add`, `_remove`), server queue purge |
| Security and latency evaluation | `server/test/e2e.test.js` |

## 5. Known limitations (state these honestly in Chapter 5)

- **Flutter client was not compiled in the environment where this was generated** (no Flutter SDK available). The Node server and crypto protocol are fully tested; the Dart crypto includes an interop test against a Node-generated message so any mismatch shows up on your first `flutter test`. Fix any version-specific compile warnings on your machine.
- **ECC (X25519) is used instead of RSA-2048** - the report allows either.
- **Local storage is RAM only**, not SQLCipher. This is the strongest form of "no forensic footprint" but chat history is lost when the app closes. To add persistence, use `sqflite_sqlcipher` keyed by a key kept in secure storage, and delete rows in `_remove`.
- **Offline queue is in server memory** (stands in for Redis) and is lost if the server restarts. Users directory is a JSON file standing in for MongoDB/PostgreSQL.
- **No forward secrecy / ratcheting** (the report excludes the Signal Double Ratchet). The long-term private key protects all past messages if stolen.
- **No public-key verification** (no safety numbers / QR check), so a malicious server could substitute keys. Mention as future work.
- **Plain HTTP in development.** For deployment put the server behind HTTPS/WSS (Nginx or Caddy) and remove `usesCleartextTraffic`.
- The Flutter UI does not block screenshots and does not use biometric key gating.
