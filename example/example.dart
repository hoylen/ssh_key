#!/usr/bin/env dart
//
// Example from README.md file.
//
// Example:
//
//     dart example.dart test-rsa-key.pem

import 'dart:io';
import 'package:ssh_key/ssh_key.dart' as ssh_key;

void main(List<String> args) {
  if (args.isEmpty) {
    stderr.write('Usage error: missing public key filename\n');
    exit(1);
  }
  if (1 < args.length) {
    stderr.write('Usage error: too many arguments\n');
    exit(1);
  }

  final filename = args[0];
  final outputFormat = ssh_key.PubKeyEncoding.sshPublicKey;
  // final outputFormat = ssh_key.PubKeyEncoding.openSSH;
  // final outputFormat = ssh_key.PubKeyEncoding.pkcs1;
  // final outputFormat = ssh_key.PubKeyEncoding.x509spki;

  // Read the file and decoding it

  final srcEncoding = File(filename).readAsStringSync();

  final pubKey = ssh_key.publicKeyDecode(srcEncoding);

  if (pubKey is ssh_key.RSAPublicKeyWithInfo) {
    // Use the RSA public key (this example just prints it out)

    stderr.write('''RSA public key:
  fingerprint: ${pubKey.fingerprint()}
  modulus: ${pubKey.n}
  public exponent: ${pubKey.publicExponent}
''');
    // The modulus and public exponent (n and e) are available,
    // because the RSAPublicKeyWithInfo is a subclass of the
    // Pointy Castle RSAPublicKey class.
  }

  // Encode the public key and printing it out

  final destEncoding = pubKey.encode(outputFormat);

  stdout.write(destEncoding);
}
