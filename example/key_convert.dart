#!/usr/bin/env dart

/// Converts a key from one format into another.
///
/// Demonstrates the use of the `publicKeyDecode` decoding function and the
/// `encode` method.
///
/// For example,
///
///     dart key_convert.dart test-rsa-key.pem -f openssh -v

import 'dart:io';

import 'package:args/args.dart';

import 'package:ssh_key/ssh_key.dart' as ssh_key;

//################################################################
// Global constants

//----------------------------------------------------------------
/// Program name

const _programName = 'key_convert';

/// Version

const _version = '1.0.0';

//################################################################

class CommandLine {
  //================================================================
  // Constructors

  //----------------------------------------------------------------

  factory CommandLine(List<String> args) {
    var verbose = false;

    final parser = ArgParser(allowTrailingOptions: true)
      ..addOption('format',
          abbr: 'f', help: 'output format', defaultsTo: defaultFormat)
      ..addFlag('verbose',
          abbr: 'v',
          help: 'output extra information when running',
          negatable: false)
      ..addFlag('help', abbr: 'h', help: 'show this message', negatable: false);

    final results = parser.parse(args);

    final prog = results.name ?? _programName;

    // Help flag

    {
      final dynamic help = results['help'];
      if (help is bool && help != false) {
        print('''Usage: $prog [options] inputKeyFile
${parser.usage}

Formats: ${formats.keys.join(', ')}
$_programName $_version''');
        exit(0);
      }
    }

    {
      final dynamic v = results['verbose'];
      verbose = (v is bool && v != false);
    }

    final dynamic formatStr = results['format'].toLowerCase();
    final outputFormat = formats[formatStr];
    if (outputFormat == null) {
      stderr.write('$prog: unknown format: $formatStr (see --help)\n');
      exit(2);
    }

    if (results.rest.length != 1) {
      if (results.rest.isEmpty) {
        stderr.write('$prog: missing input filename\n');
      } else {
        stderr.write('$prog: too many arguments\n');
      }
      exit(2);
    }
    final inputFilename = results.rest.first;

    return CommandLine._internal(inputFilename, outputFormat, verbose);
  }

  //----------------------------------------------------------------
  /// Internal constructor that sets all the final members.

  CommandLine._internal(this.inputFilename, this.outputFormat, this.verbose);

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

  final String inputFilename;

  final ssh_key.PubKeyEncoding outputFormat;

  final bool verbose;
}

//################################################################

void main(List<String> args) {
  final options = CommandLine(args);

  try {
    // Read in the key

    final srcEncoding = File(options.inputFilename).readAsStringSync();
    final key = ssh_key.publicKeyDecode(srcEncoding);

    if (options.verbose) {
      if (key is ssh_key.RSAPublicKeyWithInfo) {
        // key.source is always not null, because key was decoded from bytes
        stderr.write('Input format: ${key.source!.encoding}\n');
      }

      stderr.write('\nOutput format: ${options.outputFormat}\n');
    }

    // Write out the key in the requested format

    final destEncoding = key.encode(options.outputFormat);
    stdout..write(destEncoding)..write('\n');
  } on FileSystemException catch (e) {
    print('${options.inputFilename}: $e');
  }
}
