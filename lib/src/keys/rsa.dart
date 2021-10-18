part of ssh_key;

//################################################################
// Constants

/// The OpenSSH key type for an RSA public key.
///
/// A short string used to identify the RSA public key type in OpenSSH.
/// This value appears at the beginning of the OpenSSH format one-line text
/// representation, as well as the first chunk in the SSH Public Key file
/// format.

const _rsaKeyType = 'ssh-rsa';

/// OID that identifies the RSA Encryption algorithm.

const _rsaAlgorithmOid = '1.2.840.113549.1.1.1';

// Textual Encoding labels for the public key formats

const _rsaPublicPkcs1label = 'RSA PUBLIC KEY';
const _rsaPublicX509spkiLabel = 'PUBLIC KEY';

// Textual Encoding labels for the private key formats

const _rsaPrivatePkcs1label = 'RSA PRIVATE KEY';

//################################################################
/// An RSA public key with additional information.
///
/// This is a Pointy Castle `RSAPublicKey` extended with additional members
/// relating to encoding it in a file format. Namely, a collection of
/// [properties] and (if it was created by decoding text) [source].
///
/// Methods for encoding it in different file formats are available. But
/// normally programs can just invoke the `encode` method (defined by the
/// [PublicKeyExt] extension on the Pointy Castle `PublicKey`), with a format
/// parameter -- that will cause one of these formatting methods to be invoked.
///
/// The [fingerprint] of the public key can also be calculated.

class RSAPublicKeyWithInfo extends pointy_castle.RSAPublicKey
    with PublicKeyMixin {
  //================================================================
  // Constructors

  //----------------------------------------------------------------
  /// Constructor from RSA public values.

  RSAPublicKeyWithInfo(BigInt modulus, BigInt exponent)
      : super(modulus, exponent);

  //----------------------------------------------------------------
  /// Constructor from Pointy Castle RSAPublicKey.

  RSAPublicKeyWithInfo.fromRSAPublicKey(pointy_castle.RSAPublicKey pcKey)
      : super(pcKey.modulus!, pcKey.publicExponent!);

  //================================================================
  // Methods

  //----------------------------------------------------------------
  /// Generates a fingerprint for the RSA public key
  ///
  /// The [format] determines if the fingerprint is generated using the old
  /// "md5" approach or the new "sha256" (default).
  ///
  /// Returns a string that starts with the digest algorithm name and a colon.

  String fingerprint({FingerprintType format = FingerprintType.sha256}) {
    // See: https://coolaj86.com/articles/ssh-pubilc-key-finger(print)s/

    final data = _encodeAsChunks();
    String result;

    switch (format) {
      case FingerprintType.sha256:
        final hash = pointy_castle.SHA256Digest().process(data);
        // Base-64 without any "=" padding
        result = 'SHA256:${base64.encode(hash).replaceAll('=', '')}';
        break;

      case FingerprintType.md5:
        final hash = pointy_castle.MD5Digest().process(data);
        // Hexadecimal with colons between each byte
        result = 'MD5:${_hex(hash, separator: ':')}';
        break;
    }

    return result;
  }

  /// Represent bytes in hexadecimal
  ///
  /// If a [separator] is provided, it is placed the hexadecimal characters
  /// representing each byte. Otherwise, all the hexadecimal characters are
  /// simply concatenated together.

  static String _hex(Uint8List bytes, {String? separator}) {
    final buf = StringBuffer();
    for (final b in bytes) {
      final s = b.toRadixString(16);
      if (buf.isNotEmpty && separator != null) {
        buf.write(separator);
      }
      buf.write('${(s.length == 1) ? '0' : ''}$s');
    }
    return buf.toString();
  }

  //================================================================
  // Methods for encoding

  //----------------------------------------------------------------
  /// Utility method to encode the RSA Public Key into binary bytes.
  ///
  /// ```
  /// string  keyType
  /// mpint   publicExponent
  /// mpint   modulus
  /// ```
  /// Where _string_ is a 4-byte length followed by the string value and _mpint_
  /// is also a 4-byte length followed by the Multiple Precision Integer value.

  Uint8List _encodeAsChunks() => BinaryLengthValue.encode([
        BinaryLengthValue.fromString(_rsaKeyType), // key-type
        BinaryLengthValue.fromBigInt(exponent!), // public exponent (e)
        BinaryLengthValue.fromBigInt(modulus!) // n
      ]);

  //----------------------------------------------------------------
  /// Utility method to encode the RSA Public Key into ASN.1 DER.
  ///
  /// From [RFC 3447](https://tools.ietf.org/html/rfc3447#appendix-A.1.1):
  ///
  /// ```
  /// RSAPublicKey ::= SEQUENCE {
  ///   modulus           INTEGER,  -- n
  ///   publicExponent    INTEGER   -- e
  /// }
  /// ```

  Uint8List _pkcs1bytes() {
    final seq = ASN1Sequence()
      ..add(ASN1Integer(modulus!))
      ..add(ASN1Integer(exponent!));

    return seq.encodedBytes;
  }

  //----------------------------------------------------------------
  /// Encode an RSA public key in the OpenSSH Public Key format.
  ///
  /// Note: the OpenSSH format only supports one comment. Any additional
  /// comments and all other properties are not included in the encoding.
  ///
  /// Programs normally use `encode` method from the [PublicKeyExt] extension,
  /// with the appropriate format, which will invoke this method.

  String encodeOpenSsh() {
    final encoding = OpenSshPublicKey(_encodeAsChunks(), properties.comment);
    return encoding.encode();
  }

  //----------------------------------------------------------------
  /// Encode an RSA public key in the SSH Public Key (RFC 4716) format.
  ///
  /// If [doNotQuoteComments], double-quotes around the comment value are not
  /// included in the header value. Otherwise, double-quotes are included in the
  /// value (as permitted by section 3.3.2 of RFC 4716 and is "common
  /// practice").
  ///
  /// Programs normally use `encode` method from the [PublicKeyExt] extension,
  /// with the appropriate format, which will invoke this method.
  /// But programs will need to invoke this method directly, if they want to
  /// omit the double-quotes.

  String encodeSshPublicKey({bool doNotQuoteComments = false}) {
    // Create a list of headers from the properties
    // Note: property keys are case-insensitive, but header tags retain case

    final headers = <SshPublicKeyHeader>[];

    final tags = properties.keys.toList()..sort();
    for (final tag in tags) {
      for (final value in properties.values(tag)!) {
        headers.add(SshPublicKeyHeader(tag, value));
      }
    }

    final typeExponentModulus = _encodeAsChunks();

    return SshPublicKey(headers, typeExponentModulus)
        .encode(doNotQuoteComments: doNotQuoteComments);
  }

  //----------------------------------------------------------------
  /// Encode as PEM encoded PKCS#1 (often just called "PEM").
  ///
  /// From [RFC 3447](https://tools.ietf.org/html/rfc3447#appendix-A.1.1):
  ///
  /// ```
  /// RSAPublicKey ::= SEQUENCE {
  ///   modulus           INTEGER,  -- n
  ///   publicExponent    INTEGER   -- e
  /// }
  /// ```
  ///
  /// Programs normally use `encode` method from the [PublicKeyExt] extension,
  /// with the appropriate format, which will invoke this method.

  String encodePkcs1() {
    final container = TextualEncoding(_rsaPublicPkcs1label, _pkcs1bytes());
    return container.encode();
  }

  //----------------------------------------------------------------
  /// Encode an RSA public key in the X.509 subjectPublicKeyInfo format.
  ///
  /// Note: this format does not support comments/properties.
  ///
  /// Programs normally use `encode` method from the [PublicKeyExt] extension,
  /// with the appropriate format, which will invoke this method.

  String encodeX509spki() {
    final spki =
        SubjectPublicKeyInfo(_rsaAlgorithmOid, [ASN1Null()], _pkcs1bytes());

    final fmt = TextualEncoding(_rsaPublicX509spkiLabel, spki.encode());
    return fmt.encode();
  }
}

//----------------------------------------------------------------
/// Create an RSA public key from the OpenSSH binary format.
///
/// The binary data must contain three chunks:
///
/// 1. The algorithm key type (must be "ssh-rsa")
/// 2. RSA exponent
/// 3. RSA modulus
///
/// The encoding used by the SSH binary packet protocol for encoding
/// the "ssh-rsa" key format is defined in
/// [section 6.6 of RFC 4253](https://tools.ietf.org/html/rfc4253#section-6.6)
/// _The Secure Shell (SSH) Transport Layer Protocol_.
/// The OpenSSH implementation uses the same encoding to store RSA public keys
/// in its OpenSSH public key format or
/// the OpenSSH2 format. See [OpenSshPublicKey] and [SshPublicKey].
///
/// Throws a [KeyBad] if the _chunks_ does not contain an RSA public
/// key.
///
/// Some information on the format can be found in:
///
/// http://blog.oddbit.com/post/2011-05-08-converting-openssh-public-keys/
/// and
/// https://superuser.com/questions/1477472/openssh-public-key-file-format
///
/// https://tools.ietf.org/html/rfc4251#section-5

RSAPublicKeyWithInfo _rsaPublicFromOpenSSH(Uint8List bytes,
    {String? optionalComment, PubTextSource? source}) {
  assert(
      source == null ||
          source.encoding == PubKeyEncoding.openSsh ||
          source.encoding == PubKeyEncoding.sshPublicKey,
      'unexpected source of chunks: ${source.encoding}');

// The data should contain 3 chunks of data.
// This is a good article about the SSH RSA public key format:
// https://coolaj86.com/articles/the-ssh-public-key-format/

  final br = BinaryRange(bytes);

  // 1. Key-type

  final kt = br.nextString();
  if (kt != _rsaKeyType) {
    throw KeyBad('wrong key-type: expecting "$_rsaKeyType", got "$kt"');
  }

  // 2. Exponent

  final publicExponent = br.nextMPInt();

  // 3. Modulus

  final modulus = br.nextMPInt();

  if (br.isNotEmpty) {
    throw KeyBad('unexpected extra data in RSA public key');
  }

  // Set optional comment

  final result = RSAPublicKeyWithInfo(modulus, publicExponent)
    .._source = source;

  if (optionalComment != null) {
    result.properties.comment = optionalComment;
  }

  return result;
}

//----------------------------------------------------------------
/// Create from PKCS #1.

RSAPublicKeyWithInfo _rsaFromPkcs1(Pkcs1RsaPublicKey pkcs1) {
  final result = RSAPublicKeyWithInfo(pkcs1.modulus, pkcs1.exponent)
    .._source = pkcs1.source;

  return result;

  // Note: there is no comment, because PKCS #1 is expected to come from an
  // RFC 7468 Textual Encoding, which does not support comments nor headers.
}

//################################################################
/*
This is no longer required with Pointy Castle 2.0.0, which added its
own publicExponent. Though the `RSAPrivateKey` constructor must be
explicitly passed the value of the public exponent.

/// Extension on the Pointy Castle `RSAPrivateKey` class.
///
/// This extension defines a [publicExponent] getter, as a convenient way
/// to obtain the RSA public exponent value.

extension RSAPrivateKeyExt on pointy_castle.RSAPrivateKey {
  /// Calculates the public exponent.
  ///
  /// The Pointy Castle `RSAPrivateKey` class does not contain the public
  /// exponent available, but it can be calculated. This getter calculates

  BigInt get publicExponent {
    final phi = (p - BigInt.one) * (q - BigInt.one);
    return d.modInverse((phi));
  }
}
*/

//################################################################
/// An RSA private key with additional information.
///
/// This is a Pointy Castle `RSAPrivateKey` extended with additional members
/// relating to encoding it in a file format. Namely, an optional [comment]
/// and (if it was created by decoding text) [source].
///
/// Methods for encoding it in different file formats are available. But
/// normally programs can just invoke the `encode` method (defined by the
/// [PrivateKeyExt] extension on the Pointy Castle `PublicKey`), with a format
/// parameter -- that will cause one of these formatting methods to be invoked.

class RSAPrivateKeyWithInfo extends pointy_castle.RSAPrivateKey
    with PrivateKeyMixin {
  //================================================================
  // Constructors

  //----------------------------------------------------------------
  /// Constructor from RSA private values.
  ///
  /// Throws [ArgumentError] if the parameters are not suitable as for an RSA
  /// private key.

  RSAPrivateKeyWithInfo(
      BigInt modulus, BigInt privateExponent, BigInt p, BigInt q)
      : super(modulus, privateExponent, p, q) {
    if (p * q != modulus) {
      throw ArgumentError.value(modulus, 'modulus', 'inconsistent with p & q');
    }
  }

  //----------------------------------------------------------------
  /// Constructor from Pointy Castle RSAPrivateKey.

  RSAPrivateKeyWithInfo.fromRSAPrivateKey(pointy_castle.RSAPrivateKey pc)
      : super(pc.p! * pc.q!, pc.privateExponent!, pc.p, pc.q);

  //================================================================
  // Methods

  /// Encode into the OpenSSH Private Key format.

  String encodeOpenSshPrivateKey() {
    final parts = _encodeOpenSshPrivateParts();

    final container = OpenSshPrivateKey(
        'none', 'none', Uint8List.fromList(<int>[]), parts.item1, parts.item2);

    return TextualEncoding('OPENSSH PRIVATE KEY', container.encode()).encode();
  }

  /// Encode into the PuTTY Private Key format.

  String encodePuttyPrivateKey(String passphrase) {
    final e = _encodePuttyPrivateParts();

    return PuttyPrivateKey(
            e.keyType, 'none', e.publicBytes, e.privateBytes, e.comment)
        .encode(passphrase);
  }

  /// Encode into the PKCS#1 Private Key format.

  String encodePkcs1PrivateKey(String passphrase) {
    final b = Pkcs1RsaPrivateKey(modulus!, privateExponent!, p!, q!).encode();

    return TextualEncoding(_rsaPrivatePkcs1label, b).encode();
  }

  //----------------------------------------------------------------
  /// Encode an RSA public key in the OpenSSH public key format.
  ///
  /// Note: the OpenSSH format only supports one comment. Any additional
  /// comments and all other properties are not included in the encoding.
  ///
  /// Public bytes and private bytes

  Tuple2<Uint8List, Uint8List> _encodeOpenSshPrivateParts() {
    // Encode the public part

    final pubBytes =
        RSAPublicKeyWithInfo(modulus!, publicExponent!)._encodeAsChunks();

    // Encode the private part

    final dummyPrefix = Uint8List.fromList([0, 0, 0, 0, 0, 0, 0, 0]); // TODO

    final chunks = [
      BinaryLengthValue.fromString(_rsaKeyType),
      BinaryLengthValue.fromBigInt(modulus!),
      BinaryLengthValue.fromBigInt(publicExponent!),
      BinaryLengthValue.fromBigInt(privateExponent!),
      BinaryLengthValue.fromBigInt(q!.modInverse(p!)), // IQMP
      BinaryLengthValue.fromBigInt(p!),
      BinaryLengthValue.fromBigInt(q!),
    ];
    if (comment != null) {
      chunks.add(BinaryLengthValue.fromString(comment!));
    } else {
      chunks.add(BinaryLengthValue.fromString('')); // zero length string
    }

    final pvt = BinaryLengthValue.encode(chunks);

    // Pad the encoded private part

    // According to https://coolaj86.com/articles/the-openssh-private-key-format/
    // the block size is 8 when the key isn't encrypted
    const _pvtBlockSize = 16; // block size for the rnd+pvt+comment+pad

    final blockOverflow = ((dummyPrefix.length + pvt.length) % _pvtBlockSize);

    final padding = <int>[];
    if (blockOverflow != 0) {
      // Need to add some padding
      for (var x = 0; x < (_pvtBlockSize - blockOverflow); x++) {
        padding.add(x + 1);
      }
    }

    final paddedPvt = Uint8List.fromList(dummyPrefix + pvt + padding);
    assert(paddedPvt.length % _pvtBlockSize == 0);

    // Return the two text_encodings

    return Tuple2(pubBytes, paddedPvt);
  }

  _EncodedPuttyPrivateParts _encodePuttyPrivateParts() {
    final pubBytes =
        RSAPublicKeyWithInfo(modulus!, publicExponent!)._encodeAsChunks();

    final pvtBytes = BinaryLengthValue.encode([
      BinaryLengthValue.fromBigInt(privateExponent!),
      BinaryLengthValue.fromBigInt(p!),
      BinaryLengthValue.fromBigInt(q!),
      BinaryLengthValue.fromBigInt(q!.modInverse(p!)), // IQMP
    ]);

    return _EncodedPuttyPrivateParts(_rsaKeyType, pubBytes, pvtBytes, comment);
  }
}

//################################################################

/*
PRIVATE Key

You can recognize the PKCS#1 format by the "BEGIN RSA PRIVATE KEY" header, and
 PKCS#8 by the "BEGIN PRIVATE KEY" header. You can use dumpasn1 or
  openssl asn1parse to investigate their contents, as well as openssl rsa and openssl pkey.


Because OpenSSH uses OpenSSL for the cryptographic code (algorithms, key generation), previous versions of OpenSSH simply stored private keys using whatever format the OpenSSL functions offered – which was DER-serialized PKCS#1 'RSAPrivateKey' format (also commonly known as PEM format) most of the time. See RFC 3447 for the ASN.1 definition of the format.

(OpenSSL itself now prefers storing private keys in PKCS#8 format, which means OpenSSH can load those keys as well, although it does not write them. See RFC 5208 for the ASN.1 definition of the container format.)



Recent versions of OpenSSH have invented a new, custom format for private key files. The container format is documented in PROTOCOL.key, and the individual key formats are [probably?] the same as used by ssh-agent, which is documented in draft-miller-ssh-agent. This format uses the RFC 4251 data types.

https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key
https://tools.ietf.org/html/draft-miller-ssh-agent-02#section-4.2.1

 */

//----------------------------------------------------------------

RSAPrivateKeyWithInfo _rsaPrivateFromOpenSSH(
    Uint8List publicBytes, Uint8List privateBytes,
    [PvtTextSource? source]) {
  // Note: the comment is inside the privateBytes. First initialize it to
  // null here and then set it below (once it has been extracted from the
  // privateBytes.

  // Parse the public key block

  final pub = _rsaPublicFromOpenSSH(publicBytes);

  // Parse the private key block

  // This format is NOT PKCS #1, but here's what PKCS #1 says about the
  // numbers in a private key:
  //
  // https://tools.ietf.org/html/rfc2313 says:
  // An RSA private key logically consists of only the modulus n and the
  // private exponent d. The presence of the values p, q, d mod (p-1),
  // d mod (p-1), and q-1 mod p is intended for efficiency.
  //
  // The presence of the public exponent e is intended to make it
  // straightforward to derive a public key from the private key.

  final privateKeyRange = BinaryRange(privateBytes);

  final prefix = privateKeyRange.nextRawBytes(8); // 64-bits
  // TODO: check/use the data in the prefix
  // What is this value? It is not well documented.
  // print('${hexDump(prefix, name: 'OpenSSH private prefix')}\n');
  assert(prefix.length == 8);

  final kt = privateKeyRange.nextString();
  if (kt != _rsaKeyType) {
    throw KeyBad('unexpected key-type: $kt');
  }

  final modulus = privateKeyRange.nextMPInt(); // copy of modulus
  final publicExponent = privateKeyRange.nextMPInt(); // copy of publicExponent
  final privateExponent = privateKeyRange.nextMPInt();
  final iqmp = privateKeyRange.nextMPInt();
  final p = privateKeyRange.nextMPInt();
  final q = privateKeyRange.nextMPInt();

  final c = privateKeyRange.nextString();
  final pvtComment = c.isNotEmpty ? c : null; // comment or null

  // According to https://coolaj86.com/articles/the-openssh-private-key-format/
  // the block size is 8 when it is not encrypted
  const _pvtBlockSize = 16; // block size for the rnd+pvt+comment+pad

  // Rest of bytes (if any) is the padding
  // The first byte of the padding is 0x01, the second 0x02, etc.

  if (_pvtBlockSize < privateKeyRange.length) {
    // Amount of bytes left is more than is what is required to pad
    throw KeyBad('bad padding: ${privateKeyRange.length} bytes');
  }

  final padding = privateKeyRange.nextRawBytes(privateKeyRange.length);
  for (var x = 0; x < padding.length; x++) {
    assert(padding[x] == x + 1, 'padding does not follow 01 02 03 convention');
  }

  // Check the public key matches the private key.
  //
  // The public key part can be discarded, since it has the same numbers that is
  // in the private key part.

  if (pub.modulus != modulus || pub.publicExponent != publicExponent) {
    throw KeyBad('inconsistent: public and private keys');
  }

  if (p * q != modulus) {
    throw KeyBad('invalid RSA private key: bad modulus');
  }
  if (q.modInverse(p) != iqmp) {
    throw KeyBad('invalid RSA private key: bad (q^-1) mod p');
  }
  final phi = (p - BigInt.one) * (q - BigInt.one);
  if ((publicExponent * privateExponent) % phi != BigInt.one) {
    throw KeyBad('invalid RSA private key: bad exponents');
  }

  // Success

  return RSAPrivateKeyWithInfo(modulus, privateExponent, p, q)
    ..comment = pvtComment
    .._source = source;
}

//----------------------------------------------------------------

RSAPrivateKeyWithInfo _rsaPrivateFromPPK(
    Uint8List publicBytes, Uint8List privateBytes, String? comment,
    [PvtTextSource? source]) {
  // The PuTTY Private Key format and the contents of its public lines and
  // private lines is documented in "sshpubk.c" from the Putty source code.

  // Parse the public key data:
  //
  // string "ssh-rsa"
  // mpint  exponent
  // mpint  modulus

  final pub = _rsaPublicFromOpenSSH(publicBytes);
  // Note: the above decode will check the key-type has the correct value

  // Parse the (unencrypted) private key data
  //
  // mpint private_exponent
  // mpint p      (the larger of the two primes)
  // mpint q      (the smaller prime)
  // mpoint iqmp  (the inverse of q modulo p)
  // data padding (to reach a multiple of the cipher block size)

  final pvtRange = BinaryRange(privateBytes);

  final privateExponent = pvtRange.nextMPInt();
  final p = pvtRange.nextMPInt();
  final q = pvtRange.nextMPInt();
  final iqmp = pvtRange.nextMPInt();

  if (iqmp != q.modInverse(p)) {
    throw KeyBad('invalid iqmp value in RSA private key');
  }

  // Rest is padding
  // sha1.blockSize
  const cipherBlockSize = 0; // todo
  if (0 < cipherBlockSize && cipherBlockSize <= pvtRange.length) {
    throw KeyBad('unexpected extra data in RSA private key');
  }

  return RSAPrivateKeyWithInfo(pub.modulus!, privateExponent, p, q)
    ..comment = comment
    .._source = source;
}

//----------------------------------------------------------------

RSAPrivateKeyWithInfo _rsaPrivateFromPkcs1(Pkcs1RsaPrivateKey pkcs1) {
  final result = RSAPrivateKeyWithInfo(
      pkcs1.modulus, pkcs1.privateExponent, pkcs1.prime1, pkcs1.prime2)
    .._source = pkcs1.source;

  return result;
}
