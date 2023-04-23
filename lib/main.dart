import 'dart:convert';

import 'package:biometric_storage/biometric_storage.dart';
import 'package:cryptography/cryptography.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:local_auth/local_auth.dart';
import 'package:pinenacl/ed25519.dart';
import 'package:pinenacl/tweetnacl.dart';
import 'package:encrypt/encrypt.dart' as encrypt;

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  // This widget is the root of your application.
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Flutter Demo',
      theme: ThemeData(
        primarySwatch: Colors.blue,
      ),
      home: const MyHomePage(title: 'Flutter Demo Home Page'),
    );
  }
}

class MyHomePage extends StatefulWidget {
  const MyHomePage({super.key, required this.title});
  final String title;

  @override
  State<MyHomePage> createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  String state = 'N/A';
  BiometricStorageFile? sharedKeyStorage;
  String? saveSeed;
  String? saveSharedKey;

  Future<bool> _canAuthenticate() async {
    final auth = LocalAuthentication();
    final canAuthenticateWithBiometrics = await auth.canCheckBiometrics;
    final canAuthenticate =
        canAuthenticateWithBiometrics || await auth.isDeviceSupported();
    return canAuthenticate;
  }

  Future<void> _requestToCreateBiometricLogin() async {
    print("flutter_biometric: _requestToCreateBiometricLogin");
    final canAuthenticate = await _canAuthenticate();
    if (canAuthenticate) {
      final authenticated = await LocalAuthentication().authenticate(
        localizedReason:
            'Scan your fingerprint (or face or whatever) to authenticate',
        options: const AuthenticationOptions(
          stickyAuth: true,
          biometricOnly: true,
        ),
      );
      if (authenticated) {
        print("flutter_biometric: authenticated succeed");
        // Step1: create private key from client
        final keypair = await X25519().newKeyPair();
        final seedForBiometric = TweetNaCl.randombytes(TweetNaCl.seedSize);

        // Step2: create public key from client and verify key
        final publickey = await keypair.extractPublicKey();
        final clientPublicKey = base64.encode(publickey.bytes);

        final signingKey = SigningKey(seed: seedForBiometric);
        final verifyBiometircKey = base64.encode(signingKey.verifyKey);

        // Step3: send clientPublicKey and verifyBiometircKey to server and get serverKey back
        final serverKey =
            _submitKeyToServer(clientPublicKey, verifyBiometircKey);

        // Step4: create shared key from client and server
        final sharedKey = await _createShareKey(keypair, serverKey);

        // Step5: save sharedKey to biometric storage
        await _saveKey(sharedKey, base64.encode(seedForBiometric));
      }
    }
  }

  Future<void> _saveKey(String sharedKey, String seed) async {
    // Save both key to biometric storage
    print("flutter_biometric: saved key succeed $sharedKey, seed: $seed");
    try {
      sharedKeyStorage = await BiometricStorage().getStorage('sharedKey',
          options: StorageFileInitOptions(authenticationRequired: true));
      await sharedKeyStorage!.write('$sharedKey:$seed');
    } on PlatformException catch (e) {
      print("flutter_biometric: saved key failed $e");
    }

    setState(() {
      state = 'saved key succeed';
    });
  }

  Future<String> _createShareKey(
      KeyPair keypair, String serverSidePublicKey) async {
    final serverPublicKey = SimplePublicKey(base64.decode(serverSidePublicKey),
        type: KeyPairType.x25519);

    final sharedKey = await X25519().sharedSecretKey(
      keyPair: keypair,
      remotePublicKey: serverPublicKey,
    );
    final sharedKeyAsBytes = await sharedKey.extractBytes();
    return base64.encode(sharedKeyAsBytes);
  }

  String _submitKeyToServer(String clientPublicKey, String verifyBiometircKey) {
    // Sample of server side key
    return 'AmTk96WLdB7LuiuU3y6Tq34BA53/YZH87+HOMSK5pHk=';
  }

  Future<void> _requestToBiometricLogin() async {
    final canAuthenticate = await _canAuthenticate();
    if (canAuthenticate) {
      // Have to call everytime to get value from biometric storage
      sharedKeyStorage = await BiometricStorage().getStorage('sharedKey',
          options: StorageFileInitOptions(authenticationRequired: true));
      final saveSharedKey = await sharedKeyStorage?.read();
      if (saveSharedKey == null) return;
      print("flutter_biometric: saveSharedKey: $saveSharedKey");
      // Step1: get sharedKey from biometric storage
      final key = saveSharedKey.split(":");
      final sharedKey = key[0];

      // Step2: ask from challengString from server
      final challengeString = _askForChallengeString();

      // Step3: encrpyted challengeString with sharedKey
      final encryptedBiometricKey =
          _encryptedBiometricKey(challengeString, sharedKey);
      print("flutter_biometric: encryptedBiometricKey: $encryptedBiometricKey");

      // Step4: get accessToken by send encryptedBiometricKey, and bodyKey to server
      final accessToken = _submitBiometricKeyToServerToGetAccessToken();
      print("flutter_biometric: accessToken: $accessToken");
      setState(() {
        state = 'Login Succeed: $accessToken';
      });
      // Use accessToken into your header
      // And don't forget that this accessToken must be restricted to some features
      // final seedKEy = key[1]; will use for other encrypt/decrypt for response
    }
  }

  String _askForChallengeString() {
    // Call Network to server to get challengeString
    return 'randomChallengeString';
  }

  String _submitBiometricKeyToServerToGetAccessToken() {
    return 'dXNlckBleGFtcGxlLmNvbTpzZWNyZXQ=';
  }

  String _encryptedBiometricKey(String challengeString, String sharedKey) {
    // Encrypt challengeString with sharedKey
    final encrypter = encrypt.Encrypter(
      encrypt.AES(
        encrypt.Key.fromBase64(sharedKey),
        mode: encrypt.AESMode.cbc,
      ),
    );

    final iv = encrypt.IV.fromSecureRandom(16);
    final encrypted = encrypter.encrypt(
      challengeString,
      iv: iv,
    );

    return base64.encode(iv.bytes + encrypted.bytes);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(widget.title),
      ),
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: <Widget>[
            Text(state),
            const SizedBox(height: 100),
            TextButton(
                onPressed: _requestToCreateBiometricLogin,
                child: const Text("Start Biometric Login")),
            const SizedBox(height: 40),
            TextButton(
                onPressed: _requestToBiometricLogin,
                child: const Text("Login with Biometric")),
          ],
        ),
      ),
    );
  }
}
