#!/usr/bin/env dart

/// Generates an RSA key pair and uses the encoding methods to print them out.
///
/// Demonstrates the use of the `encode` method for both public and private
/// keys.
///
/// For example,
///
///     dart key_generate.dart --bitlength 2048

import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:args/args.dart';
import 'package:pointycastle/pointycastle.dart';

import 'package:ssh_key/ssh_key.dart' as ssh_key;

//################################################################
// Global constants

//----------------------------------------------------------------
/// Program name

const _programName = 'key_generate';

/// Version

const _version = '1.0.0';

const defaultBitLength = 2048;

//################################################################
/// Secure random number generator to use when generating keys.

//----------------------------------------------------------------
/// Creates a secure random number generator.

SecureRandom getSecureRandom() {
    // _defaultSecureRandom = FortunaRandom();
   final _defaultSecureRandom = SecureRandom('Fortuna');

    // Set a random seed

    final random = Random.secure();
    final seeds = <int>[];
    for (var i = 0; i < 32; i++) {
      seeds.add(random.nextInt(255));
    }

    _defaultSecureRandom.seed(KeyParameter(Uint8List.fromList(seeds)));

  // Return it

  return _defaultSecureRandom;
}

//################################################################

//----------------------------------------------------------------
/// Generate a new RSA public-private key-pair.
///
/// This implementation uses the PointyCastle implementation of the
/// cryptographic algorithms.
///
/// The [bitLength] is used as the key length. If no value is provided, the
/// default of 2048 bits is used.
///
/// If provided, the [secureRandom] is used for random numbers. Otherwise,
/// an internal secure random number generator is used.
///
/// Returns a tuple where the first item is the public key and the second item
/// is the private key.

AsymmetricKeyPair<PublicKey, PrivateKey> _generatePointyCastleImpl(
    int bitLength, SecureRandom secureRandom) {

  // Use crypto library to generate keys

  final keyGenerator = KeyGenerator('RSA')
    ..init(ParametersWithRandom(
        RSAKeyGeneratorParameters(
            BigInt.parse('65537'), bitLength, 64),
        secureRandom));

  return keyGenerator.generateKeyPair();
}

//################################################################

class CommandLine {
  //================================================================
  // Constructors

  //----------------------------------------------------------------

  factory CommandLine(List<String> args) {
    final parser = ArgParser(allowTrailingOptions: true)
      ..addOption('bitlength',
          abbr: 'b', help: 'bit length (default: $defaultBitLength)',
          defaultsTo: '$defaultBitLength')
      ..addOption('format',
          abbr: 'f',
          help: 'output format for the public key',
          defaultsTo: defaultFormat)
      ..addFlag('help', abbr: 'h', help: 'show this message', negatable: false);

    final results = parser.parse(args);

    final prog = results.name ?? _programName;

    // Help flag

    {
      final dynamic help = results['help'];
      if (help is bool && help != false) {
        print('''Usage: $prog [options]
${parser.usage}

Formats: ${formats.keys.join(', ')}
$_programName $_version''');
        exit(0);
      }
    }

    // Bit length

    var bitLength = defaultBitLength;

    try {
      final dynamic optArg = results['bitlength'];
      if (optArg is String) {
        bitLength = int.parse(optArg);
        if (bitLength <= 0) {
          stderr.write('$prog: bit length cannot be negative\n');
          exit(2);
        }
      } else {
        assert(false);
      }
    } on FormatException {
      stderr.write('$prog: bit length is not an integer\n');
      exit(2);
    }

    // Output format

    var outFormatPub = formats[defaultFormat]!;

    final dynamic optArg = results['format'];
    if (optArg is String) {
      final formatStr = optArg.toLowerCase();
      final fmt = formats[formatStr];
      if (fmt != null) {
        outFormatPub = fmt;
      } else {
        stderr.write('$prog: unknown format: $formatStr (see --help)\n');
        exit(2);
      }
    } else {
      assert(false);
    }

    if (results.rest.isNotEmpty) {
      stderr.write('$prog: too many arguments\n');
      exit(2);
    }

    return CommandLine._internal(bitLength, outFormatPub);
  }

  //----------------------------------------------------------------

  CommandLine._internal(this.bitLength, this.outFormatPub);

  //================================================================
  // Constants

  // Available formats (with aliased names)

  static const formats = {
    // OpenSSH public key format (proprietary to OpenSSH) -- one line
    'openssh': ssh_key.PubKeyEncoding.openSsh,

    // SSH Public Key Format (RFC 4716)
    'sshpublickey': ssh_key.PubKeyEncoding.sshPublicKey,
    'rfc4716': ssh_key.PubKeyEncoding.sshPublicKey,
    'ssh': ssh_key.PubKeyEncoding.sshPublicKey,
    'ssh2': ssh_key.PubKeyEncoding.sshPublicKey,

    // Textual encoded PKCS #1 (OpenSSH calls this "pem")
    'pkcs1': ssh_key.PubKeyEncoding.pkcs1,
    'pem': ssh_key.PubKeyEncoding.pkcs1,

    // Textual encoded subjectPublicKeyInfo from X.509 (proprietary to OpenSSH)
    'x509spki': ssh_key.PubKeyEncoding.x509spki,
    'pkcs8': ssh_key.PubKeyEncoding.x509spki,
  };

  static const defaultFormat = 'sshpublickey';

  //================================================================
  // Members

  int bitLength;

  ssh_key.PubKeyEncoding outFormatPub;
}

//################################################################

void main(List<String> args) {
  final options = CommandLine(args);

  try {
    final pair = _generatePointyCastleImpl(options.bitLength, getSecureRandom());

    // Print out the keys

    final pubText = pair.publicKey.encode(options.outFormatPub);
    print(pubText);

    final pvtText = pair.privateKey.encode(ssh_key.PvtKeyEncoding.openSsh);
    print(pvtText);
  } on FileSystemException catch (e) {
    stderr.write('error: $e\n');
    exit(1);
  }
}
