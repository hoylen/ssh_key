# ssh_key

Encodes and decodes keys to/from different text file formats.

## Introduction

This package allows public keys and private keys to be decoded from
different text file formats. And for them to be encoded into those
formats.

The primary focus is on the file formats used by implementations of
SSH. But some of these formats are also used by other programs; and
there is no fundamental reason why other key file formats can't be
supported.

SSH implementations use a number of different file formats to
represent public-keys. While the SSH wire-protocol is standardized,
the storage of keys was an implementation detail that was left
undefined. Consequently, different implementations have used different
(often proprietary) file formats to store their keys.

### Formats

These **public key** formats are supported:

- OpenSSH Public Key (single-line format used by older versions of
  OpenSSH);

- SSH Public Key (defined by RFC 4716 and used by newer versions of
  OpenSSH);

- Textual encoding of PKCS #1 (OpenSSH calls this "PEM", which is
  an ambiguous term);

- Textual encoding of subjectPublicKeyInfo from X.509 (OpenSSH
  incorrectly refers to this as "PKCS #8"; the real PKCS #8 is a
  format for representing a _private_ key)

### Public-key algorithms

This public-key algorithm is supported:

- RSA

## Example

This example shows the decoding of a String into either a publc key or
a private key, using `publicKeyDecode` and `privateKeyDecode`
respectively.

It also shows the encoding of a public key and private key into a
String, using the `encode` method on the key.

```dart
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
```

## Know limitations

- Only RSA keys are supported.

- Requires Dart 2.7.0 or later, because it uses Dart _extension
  methods_ to make the _encode_ method available on the Pointy
  Castle public and private key classes.

- Private key support is _very experimental_ at this
  stage. Interoperability is not guaranteed!
   - OpenSSH private key format: medium
   - PuTTY Private Key format: poor
   - PKCS#1 private key format: good

- Private keys protected by a passphrase are not supported.


This package uses the public-key classes from the [Pointy Castle
package](https://pub.dev/packages/pointycastle). Mainly because it has
classes to represent RSA keys, and implements symmetric encryption
algorithms (which will be needed when support for encrypted private
keys is added). In theory, this package could have been independent of
any cryptographic package, but it would then have to implement its own
classes for representing the keys.

_Note: support for other formats is limited by the lack of
documentation about the format (since they are often proprietary).
Support for other types of keys is limited by the implementation of
other cryptographic algorithms in Dart._

## Which library to use

Three libraries are provided by this package.

Most programs should only need to use the _ssh_key_ library.  The
other two libraries are for internal use by the _ssh_key_ library.

``` dart
import 'package:ssh_key/ssh_key.dart' as ssh_key;
```
