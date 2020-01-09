/// Encoding and decoding public and private keys.
///
/// The file formats supported by this library focuses on formats used by
/// various implementations of the SSH protocol. But some of the formats are
/// used by other programs too.
///
/// Currently, this library only supports public and private keys using the RSA
/// algorithm.
///
/// See the [PubKeyEncoding] and [PvtKeyEncoding] enumerations for the file
/// formats that are supported. Some of these formats can represent additional
/// information besides the key (namely a comment and/or other attributes).
/// That additional information is supported by the decoding and encoding
/// operations implemented in this library.
///
/// ### Decoding keys
///
/// #### Decoding public keys
///
/// To decode text into a public key, use the [publicKeyDecode] function.
/// It returns an instance of the abstract Pointy Castle class
/// `PublicKey`. Its type should be determined and then up-casted
/// into that class to access additional members and methods.
///
/// For example, into a PointyCastle `RSAPublicKey` to use it as an RSA public
/// key, or into a _ssh_key_ [RSAPublicKeyWithInfo] to access any
/// comments/properties that were in the text.
///
/// ```dart
/// final k = publicKeyDecode(str);
/// if (k is RSAPublicKeyWithInfo) {
///   final rsaKey = k as RSAPublicKeyWithInfo;
///   // rsaKey is a PointyCastle RSAPublicKey with additional properties
///   // and methods.
/// }
/// ```
///
/// When there are multiple public keys to be decoded (such as in the OpenSSH
/// _authorized_keys_ file), use the [publicKeyDecodeAll] function.
///
/// #### Decoding private keys
///
/// Note: private key support is currently experimental, and only supports
/// private keys that are not protected by a passphrase.
///
/// To decode text into a private key, use the [privateKeyDecode] function.
/// It returns an instance of the abstract Pointy Castle class
/// `PrivateKey`. Its type should be determined and then up-casted
/// into that class to access additional members and methods.
///
/// For example, casting it into a PointyCastle `RSAPrivateKey`
/// to use it as an RSA private key, or into a [RSAPrivateKeyWithInfo] to access any
/// comment that was in the encoding.
///
/// ### Encoding keys
///
/// #### Encoding public keys
///
/// To encode a public key into text, use the `encode` method on the public
/// key.
///
/// That method is defined in the [PublicKeyExt] extension on the Pointy
/// Castle `PublicKey` class. Therefore, it can be invoked on a PublicKey
/// or a subclass (e.g. RSAPublicKey or RSAPublicKeyWithInfo).
///
/// ```dart
/// RSAPublicKey k = ...
/// String text = k.encode(PubKeyEncoding.pkcs1);
/// ```
///
/// #### Encoding private keys
///
/// To encode a private key into text, use the `encode` method on the private
/// key.
///
/// That method is defined in the [PrivateKeyExt] extension on the Pointy
/// Castle `PrivateKey` class. Therefore, it can be invoked on a PrivateKey
/// or a subclass (e.g. RSAPrivateKey or RSAPrivateKeyWithInfo).

library ssh_key;

//----------------------------------------------------------------

import 'dart:collection';
import 'dart:convert';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:tuple/tuple.dart';

// This package uses the PointyCastle package for the hashing algorithms
// (instead of the crypto package, which only supports hashing algorithms),
// because encryption algorithms will be needed when support for encrypted
// private keys is implemented.

import 'package:pointycastle/export.dart' as pointy_castle;

import 'package:ssh_key/ssh_key_bin.dart';
import 'package:ssh_key/ssh_key_txt.dart';

//----------------------------------------------------------------

part 'src/keys/enums.dart';
part 'src/keys/exceptions.dart';
part 'src/keys/key_private.dart';
part 'src/keys/key_public.dart';
part 'src/keys/properties.dart';
part 'src/keys/rsa.dart';
