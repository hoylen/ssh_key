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

const _version = '2.0.0';

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
        RSAKeyGeneratorParameters(BigInt.parse('65537'), bitLength, 64),
        secureRandom));

  return keyGenerator.generateKeyPair();
}

//################################################################

class Options {
  //================================================================
  // Constructors

  //----------------------------------------------------------------

  factory Options(List<String> args) {
    var prog = _programName;

    try {
      const _optionOutput = 'output';
      const _optionForce = 'force';
      const _optionBitLength = 'bitlength';
      const _optionsFormatPublic = 'public';
      const _optionsFormatPrivate = 'private';

      final parser = ArgParser(allowTrailingOptions: true)
        ..addOption(_optionOutput,
            abbr: 'o',
            help: 'output files for keys (default: stdout)',
            valueHelp: 'FILENAME')
        ..addFlag(_optionForce,
            abbr: 'f',
            help: 'overwrite output files if it exists',
            negatable: false)
        ..addOption(_optionBitLength,
            abbr: 'b',
            help: 'bit length (default: $defaultBitLength)',
            defaultsTo: '$defaultBitLength')
        ..addOption(_optionsFormatPublic,
            abbr: 'p',
            help: 'output format for the public key',
            valueHelp: 'PUBLIC_KEY_FORMAT',
            defaultsTo: defaultFormatPublic)
        ..addOption(_optionsFormatPrivate,
            abbr: 's',
            help: 'output format for the private key',
            valueHelp: 'PRIVATE_KEY_FORMAT',
            defaultsTo: defaultFormatPrivate)
        ..addFlag('help',
            abbr: 'h', help: 'show this message', negatable: false);

      final results = parser.parse(args);
      if (results.name != null) {
        prog = results.name!;
      }

      // Help flag

      {
        final dynamic help = results['help'];
        if (help is bool && help != false) {
          stdout.write('''Usage: $prog [options]
${parser.usage}

Public key formats:
${formatHelp(formatsPublic)}
Private key formats:
${formatHelp(formatsPrivate)}
$_programName $_version
''');
          exit(0);
        }
      }

      // Output filename

      var output = results[_optionOutput];
      if (output != null && output.isEmpty) {
        output = null;
      }

      // Force overwriting of existing files

      var force = results[_optionForce] as bool;

      // Bit length

      var bitLength = defaultBitLength;

      try {
        final dynamic optArg = results[_optionBitLength];
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

      // Output format for the public key

      var outFormatPub = formatsPublic[defaultFormatPublic]!;

      final dynamic optArgPub = results[_optionsFormatPublic];
      if (optArgPub is String) {
        final f = optArgPub.toLowerCase();
        final fmt = formatsPublic[f];
        if (fmt != null) {
          outFormatPub = fmt;
        } else {
          stderr.write('$prog: unknown public key format: $f (see --help)\n');
          exit(2);
        }
      } else {
        assert(false);
      }

      // Output format for the private key

      var outFormatPvt = formatsPrivate[defaultFormatPrivate]!;

      final dynamic optArgPvt = results[_optionsFormatPrivate];
      if (optArgPvt is String) {
        final f = optArgPvt.toLowerCase();
        final fmt = formatsPrivate[f];
        if (fmt != null) {
          outFormatPvt = fmt;
        } else {
          stderr.write('$prog: unknown private key format: $f (see --help)\n');
          exit(2);
        }
      } else {
        assert(false);
      }

      // Rest

      if (results.rest.isNotEmpty) {
        stderr.write('$prog: too many arguments\n');
        exit(2);
      }

      return Options._internal(
          output, force, bitLength, outFormatPub, outFormatPvt);
    } on FormatException catch (e) {
      stderr.write('$prog: usage error: ${e.message}\n');
      exit(2);
    }
  }

  //----------------------------------------------------------------

  Options._internal(String? outputFilename, this.force, this.bitLength,
      this.outFormatPub, this.outFormatPvt) {
    // Set up the files (if required)

    if (outputFilename != null) {
      // Output keys into separate files instead of stdout

      String basename = outputFilename;
      String? pubExtension;
      String? pvtExtension;

      final startOfExtension = outputFilename.lastIndexOf('.'); // or -1
      if (0 <= startOfExtension) {
        final extension = outputFilename.substring(startOfExtension + 1);
        if (['pub', 'public', 'pem'].contains(extension)) {
          basename = outputFilename.substring(0, startOfExtension);
          pubExtension = extension;
        } else if (['private', 'pvt', 'key', 'ppk'].contains(extension)) {
          basename = outputFilename.substring(0, startOfExtension);
          pvtExtension = extension;
        }
      }

      // Use default extension, if none has been set from the output file name

      if (pubExtension == null) {
        if (outFormatPub == ssh_key.PubKeyEncoding.openSsh) {
          pubExtension = 'pub'; // default for the one-line old OpenSSH format
        } else {
          pubExtension = 'public'; // default
        }
      }

      if (pvtExtension == null) {
        if (outFormatPvt == ssh_key.PvtKeyEncoding.puttyPrivateKey) {
          pvtExtension = 'ppk'; // default for PuTTY Private Key
        } else {
          pvtExtension = 'private'; // default
        }
      }

      while (basename.endsWith('.')) {
        basename = basename.substring(0, basename.length - 1);
      }
      if (basename.isEmpty || basename.endsWith('/')) {
        throw FormatException('invalid output file name');
      }

      publicFile = File('$basename.$pubExtension');
      privateFile = File('$basename.$pvtExtension');
    } else {
      publicFile = null;
      privateFile = null;
    }
  }

  //================================================================
  // Constants

  // Available formats (with aliased names)

  static const formatsPublic = {
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

  static const formatsPrivate = {
    // OpenSSH public key format (proprietary to OpenSSH) -- one line
    'openssh': ssh_key.PvtKeyEncoding.openSsh,

    // Putty
    'puttyprivatekey': ssh_key.PvtKeyEncoding.puttyPrivateKey,
    'putty': ssh_key.PvtKeyEncoding.puttyPrivateKey,
    'ppk': ssh_key.PvtKeyEncoding.puttyPrivateKey,

    // PKCS#1
    'pkcs1': ssh_key.PvtKeyEncoding.pkcs1,
  };

  static const defaultFormatPublic = 'sshpublickey';
  static const defaultFormatPrivate = 'openssh';

  //================================================================
  // Members

  late final File? publicFile;
  late final File? privateFile;

  final bool force;

  final int bitLength;

  final ssh_key.PubKeyEncoding outFormatPub;

  final ssh_key.PvtKeyEncoding outFormatPvt;

  // Help for available formats.

  static String formatHelp(Map<String, dynamic> formats) {
    final buf = StringBuffer();

    final uniqueValues = {for (var x in formats.values) x: null}.keys;

    for (final value in uniqueValues) {
      var num = 0;
      for (final name in formats.keys) {
        if (formats[name] == value) {
          num++;
          if (num == 1) {
            buf.write('  "$name"');
          } else if (num == 2) {
            buf.write(' (alias: "$name"');
          } else {
            buf.write(', "$name"');
          }
        }
      }
      if (1 < num) {
        buf.write(')');
      }
      buf.write('\n');
    }

    return buf.toString();
  }
}

//################################################################

void main(List<String> args) {
  final options = Options(args);

  try {
    final pair =
        _generatePointyCastleImpl(options.bitLength, getSecureRandom());

    // Print out the keys

    final pubText = pair.publicKey.encode(options.outFormatPub);

    final pvtText = pair.privateKey.encode(options.outFormatPvt);

    if (!options.force) {
      // Check if files already exists: do not overwrite them
      for (final f in [options.publicFile, options.privateFile]) {
        if (f != null && f.existsSync()) {
          stderr.write('error: file exists (use --force to overwrite): $f\n');
          exit(1);
        }
      }
    }

    // Output the keys

    if (options.publicFile != null) {
      options.publicFile!.writeAsStringSync(pubText);
    } else {
      stdout.writeln(pubText);
    }

    if (options.privateFile != null) {
      options.privateFile!.writeAsStringSync(pvtText);
    } else {
      stdout.writeln(pvtText);
    }
  } on FileSystemException catch (e) {
    stderr.write('error: $e\n');
    exit(1);
  }
}
