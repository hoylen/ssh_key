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

These public key formats are supported:

- OpenSSH Public Key (single-line format)

- SSH Public Key (defined by RFC 4716, sometimes called "SSH2")

- Textual encoding of PKCS #1 (OpenSSH calls this "PEM")

- Textual encoding of subjectPublicKeyInfo from X.509 (OpenSSH
  incorrectly calls this "PKCS #8")

### Public-key algorithms

This public-key algorithm is supported:

- RSA

## Example

```dart
import 'dart:io';
import 'package:ssh_key/ssh_key.dart' as ssh_key;

void main(List<String> args) {
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
  public exponent: ${pubKey.e}
''');
    // The modulus and public exponent (n and e) are available,
    // because the RSAPublicKeyWithInfo is a subclass of the
    // Pointy Castle RSAPublicKey class.
  }

  // Encode the public key and printing it out

  final destEncoding = pubKey.encode(outputFormat);

  stdout.write(destEncoding);
}
```

## Know limitations

- Only RSA keys are supported.

- Requires Dart 2.7.0 or later, because it uses Dart _extension
  methods_ to make the _encode_ method to available on the Pointy
  Castle public and private key classes.

- Private key support is experimental and only supports private keys
  that have not been protected by a passphrase. Private key formats:
    - PKCS #1 (as used by OpenSSH)
    - PuTTY Private Key (.PPK)

This package uses the public-key classes from the [Pointy Castle
package](https://pub.dev/packages/pointycastle). Mainly because it has
classes to represent RSA keys, and implements symmetric encryption
algorithms (which will be needed when support for encrypted private
keys is added). In theory, this package could have been independent of
any cryptographic package, but it would then have to implement its own
classes for reprsenting the keys.

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
