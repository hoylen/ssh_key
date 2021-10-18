#!/usr/bin/env dart
//
// Example from README.md file.
//
// Parses a file as either a public key or a private key. Optionally printing
// out the parameters of the key and/or the key in a different format.
//
// Example:
//
//     dart example.dart --public --verbose test-rsa-public-key.pem
//     dart example.dart --public test-rsa-public-key.pem --openssh
//     dart example.dart --help

import 'dart:io';
import 'package:ssh_key/ssh_key.dart' as ssh_key;

void processPublic(String str, bool verbose, ssh_key.PubKeyEncoding? format) {
  // Decode a public key

  final pubKey = ssh_key.publicKeyDecode(str);

  // Output the values in the public key

  if (verbose) {
    if (pubKey is ssh_key.RSAPublicKeyWithInfo) {
      // Use the RSA public key
      //
      // This example just prints out the RSA parameters to stderr (so only
      // encoded output goes to stdout).

      stderr.write('''RSA public key:
  modulus: ${pubKey.n}
  public exponent: ${pubKey.publicExponent}
  fingerprint: ${pubKey.fingerprint()}

''');
    } else {
      stderr.writeln('Error: recognised public key, but not RSA');
      exit(1);
    }
  }

  // Encode the public key

  if (format != null) {
    final destEncoding = pubKey.encode(format);
    stdout.write(destEncoding);
  }
}

void processPrivate(String str, bool verbose, ssh_key.PvtKeyEncoding? format) {
  // Decode a private key

  final privateKey = ssh_key.privateKeyDecode(str);

  // Output the values in the private key

  if (verbose) {
    if (privateKey is ssh_key.RSAPrivateKeyWithInfo) {
      // Use the RSA private key
      //
      // This example just prints out the RSA parameters to stderr (so only
      // encoded output goes to stdout).

      stderr.write('''RSA public key:
  modulus: ${privateKey.modulus}
  public exponent: ${privateKey.publicExponent}
  private exponent: ${privateKey.privateExponent}
  prime1 (p): ${privateKey.p}
  prime2 (q): ${privateKey.q}

''');
    } else {
      stderr.writeln('Error: recognised private key, but not RSA');
      exit(1);
    }
  }

  // Encode the private key

  if (format != null) {
    final destEncoding = privateKey.encode(format);
    stdout.write(destEncoding);
  }
}

/// Command line options

class Options {
  /// Parse the command line arguments.

  Options(List<String> args) {
    bool showHelp = false;
    String? outputFormatArg;
    final filenames = <String>[];

    for (final arg in args) {
      if (arg.startsWith('-')) {
        switch (arg) {
          case '--public':
            isPublic = true;
            break;
          case '--private':
          case '--secret':
          case '-s':
            isPublic = false;
            break;
          case '--verbose':
          case '-v':
            verbose = true;
            break;
          case '--help':
          case '-h':
            showHelp = true;
            break;
          case '--openssh':
          case '--sshpublickey':
          case '--pkcs1':
          case '--x509spki':
          case '--puttyprivatekey':
            outputFormatArg = arg;
            break;
          default:
            stderr.write('Usage error: unknown option: $arg (-h for help)\n');
            exit(2);
        }
      } else {
        filenames.add(arg);
      }
    }

    if (filenames.isEmpty) {
      stderr.write('Usage error: missing filename (-h for help)\n');
      exit(2);
    } else if (filenames.length == 1) {
      filename = filenames.first;
    } else {
      stderr.write('Usage error: too many arguments (-h for help)\n');
      exit(2);
    }

    // Set output format, if requested

    if (isPublic) {
      if (outputFormatArg != null) {
        publicKeyOutFormat = {
          '--openssh': ssh_key.PubKeyEncoding.openSsh,
          '--sshpublickey': ssh_key.PubKeyEncoding.sshPublicKey,
          '--pkcs1': ssh_key.PubKeyEncoding.pkcs1,
          '--x509spki': ssh_key.PubKeyEncoding.x509spki,
        }[outputFormatArg];
        if (publicKeyOutFormat == null) {
          stderr.writeln('Error: $outputFormatArg not for a public key');
          exit(2);
        }
      }
    } else {
      if (outputFormatArg != null) {
        privateKeyOutFormat = {
          '--openssh': ssh_key.PvtKeyEncoding.openSsh,
          '--puttyprivatekey': ssh_key.PvtKeyEncoding.puttyPrivateKey,
          '--pkcs1': ssh_key.PvtKeyEncoding.pkcs1,
        }[outputFormatArg];
        if (privateKeyOutFormat == null) {
          stderr.writeln('Error: $outputFormatArg not for a private key');
          exit(2);
        }
      }
    }

    if (showHelp) {
      stderr.write('''
Usage: example [options] filename
Options:
  --public    file contains a public key (default)
  --private   file contains a private key
  --verbose   show the key parameters

Output format for public keys:  
  --openssh       old OpenSSH public key format (one line)
  --sshpublickey  new OpenSSH public key format (RFC 4716)
  --pkcs1         PKCS#1 public key format
  --x509spki      X.509 SubjectPublicKeyInformation (incorrectly called PKCS#8)

Output format for private keys only:
  --openssh          OpenSSH format (old format)
  --puttyprivatekey  PuTTY Private Key (PPK) format
  --pkcs1            PKCS#1 private key format
''');
      exit(0);
    }
  }

  bool isPublic = true;
  late String filename;

  bool verbose = false;

  ssh_key.PubKeyEncoding? publicKeyOutFormat;
  ssh_key.PvtKeyEncoding? privateKeyOutFormat;
}

void main(List<String> args) {
  // Parse command line arguments

  final options = Options(args);

  // Read the file contents

  final srcEncoding = File(options.filename).readAsStringSync();

  // Parse the contents and output the results

  if (options.isPublic) {
    processPublic(srcEncoding, options.verbose, options.publicKeyOutFormat);
  } else {
    processPrivate(srcEncoding, options.verbose, options.privateKeyOutFormat);
  }
}
