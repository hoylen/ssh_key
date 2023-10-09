# Changelog

## 1.0.0

- Upgraded to require a minimum of Dart 3.0.0.
- Upgrade dependencies: removing tuple and requiring pointycastle v3.7.3.

## 0.8.0

- Support for unencrypted PKCS#1 private keys.
- Fixed parsing bug when there is no comment in an OpenSSH public key.
- Made members of BinaryRange private.
- Added GenericPublicKey for other key-types in the OpenSSH Public Key format.
- Added coverage and some more unit tests.

## 0.7.1

- Avoiding pointycastle v3.1.3: has a bug preventing JavaScript compilation.
- Added lints package.

## 0.7.0

- Null safety pre-release.

## 0.6.1

- Updated dependency on pointycastle to v2.0.1.

## 0.6.0

- Updated dependency on pointycastle to v2.0.0.
- Updated dependency on asn1lib to v0.8.1.

## 0.5.1

- Updated dependency on asn1lib to v0.6.4.

## 0.5.0

- Initial release.
