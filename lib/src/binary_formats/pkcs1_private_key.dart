part of ssh_key_bin;

//################################################################
/// PKCS #1 version 2.0 representation of an RSA private key.
///
/// This class can be used to:
///
/// - Decode a sequence of bytes into the parameters for an RSA private key
///   using the [decode] constructor; or
/// - Encode the parameters for an RSA private key into a sequence of bytes
///   using the [encode] method.
///
/// This class only exposes the [modulus], [privateExponent], [prime1] and
/// [prime2] RSA parameters, even though the binary format includes other
/// parameters.
///
/// ## Format
///
/// This binary format is defined in
/// [RFC 2437](https://tools.ietf.org/html/rfc2437#section-11.1.2)
/// _PKCS #1: RSA Cryptography Specifications, Version 2.0_
/// by this ASN.1 type:
///
/// ```text
/// RSAPrivateKey ::= SEQUENCE {
///   version Version,
///   modulus INTEGER, -- n
///   publicExponent INTEGER, -- e
///   privateExponent INTEGER, -- d
///   prime1 INTEGER, -- p
///   prime2 INTEGER, -- q
///   exponent1 INTEGER, -- d mod (p-1)
///   exponent2 INTEGER, -- d mod (q-1)
///   coefficient INTEGER -- (inverse of q) mod p }
///
/// Version ::= INTEGER
/// ```
/// Where:
///
/// - version is the version number, for compatibility with future
//    revisions of this document. It shall be 0 for RFC 2437.
/// - modulus is the modulus n.
/// - publicExponent is the public exponent e.
/// - privateExponent is the private exponent d.
/// - prime1 is the prime factor p of n.
/// - prime2 is the prime factor q of n.
/// - exponent1 is d mod (p-1).
/// - exponent2 is d mod (q-1).
/// - coefficient is the Chinese Remainder Theorem coefficient q-1 mod p.
///
/// This implementation only supports a value of 0 for the _version_ object.
///
/// The ASN.1 type is identical in PKCS #1 version 1.5
/// ([RFC 2313](https://datatracker.ietf.org/doc/html/rfc2313#section-7.2)).
///
/// Version of PKCS #1 newer than version 2.0 are not supported.
/// The ASN.1 type in PKCS #1 version 2.1
/// ([RFC 3447](https://datatracker.ietf.org/doc/html/rfc3447#appendix-A.1.2))
/// and PKCS #1 version 2.2
/// ([RFC 8017](https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.1.2))
/// are identified by a value of 1 for the _version_ object.
/// The _decode_ constructor will throw an exception if the value of the
/// _version_ object is not 0.

class Pkcs1RsaPrivateKey implements BinaryFormat {
  //================================================================
  // Constructors

  //----------------------------------------------------------------
  /// Constructor.
  ///
  /// Create a Pkcs1RsaPrivateKey from the modulus (n), private exponent (d),
  /// prime 1 (p) and prime 2 (q).

  Pkcs1RsaPrivateKey(
      this.modulus, this.privateExponent, this.prime1, this.prime2)
      : source = null {
    _version = BigInt.zero;

    // Calculate the other members

    final phi = (prime1 - BigInt.one) * (prime2 - BigInt.one);
    _publicExponent = privateExponent.modInverse(phi);

    _exponent1 = privateExponent % (prime1 - BigInt.one);
    _exponent2 = privateExponent % (prime2 - BigInt.one);
    _coefficient = prime2.modInverse(prime1);

    final notCorrect = _isCorrect();
    if (notCorrect != null) {
      throw ArgumentError(notCorrect);
    }
  }

  //----------------------------------------------------------------
  /// Decode from a sequence of bytes.

  Pkcs1RsaPrivateKey.decode(Uint8List data, this.source) {
    String msg;

    try {
      List<ASN1Object> objects;

      try {
        objects = _asn1parseAll(data);
      } on ASN1Exception catch (e) {
        throw _Pkcs1Msg('ASN.1 encoding bad: ${e.message}');
      } catch (e) {
        throw _Pkcs1Msg('ASN.1 encoding bad: $e');
      }

      if (objects.length != 1) {
        throw _Pkcs1Msg('ASN.1 encoding has an incorrect number of objects'
            ' (expecting 1, got ${objects.length})');
      }

      final topSequence = objects.first;
      if (topSequence is ASN1Sequence) {
        const _numberOfIntegers = 9;

        if (topSequence.elements.length != _numberOfIntegers &&
            topSequence.elements.length != _numberOfIntegers + 1) {
          final expecting = '$_numberOfIntegers or ${_numberOfIntegers + 1}';
          throw _Pkcs1Msg('ASN.1 sequence has wrong length'
              ' (expecting $expecting, got ${topSequence.elements.length})');
        }

        // Check the mandatory objects in the sequence are ASN.1 Integers

        final values = <BigInt>[];

        for (int x = 0; x < _numberOfIntegers; x++) {
          final n = topSequence.elements[x];
          if (n is ASN1Integer) {
            values.add(n.valueAsBigInteger);
          } else {
            throw _Pkcs1Msg('ASN.1 sequence item $x is not an ASN.1 Integer');
          }
        }

        // Populate the members with the ASN.1 Integer values

        var i = 0;
        _version = values[i++];
        modulus = values[i++];
        _publicExponent = values[i++];
        privateExponent = values[i++];
        prime1 = values[i++];
        prime2 = values[i++];
        _exponent1 = values[i++];
        _exponent2 = values[i++];
        _coefficient = values[i++];
        assert(i == _numberOfIntegers);

        // Check the values are sane (including whether version == 0)

        final notCorrect = _isCorrect();
        if (notCorrect != null) {
          throw _Pkcs1Msg(notCorrect);
        }

        if (_numberOfIntegers < topSequence.elements.length) {
          // version=0 does not have any other objects in the sequence.
          //
          // version==1 can have an additional "otherPrimeInfos" object, but
          // this implementation currently does not support version==1.
          throw _Pkcs1Msg('ASN.1 sequence has unexpected item');
        }

        return; // success
      } else {
        throw _Pkcs1Msg('ASN.1 encoding is not a sequence');
      }
    } on _Pkcs1Msg catch (e) {
      msg = e.message;
    } catch (e) {
      msg = 'unexpected: $e';
    }

    throw KeyBad('invalid PKCS #1 private key: $msg');
  }

  //================================================================
  // Members

  /// Version number of the format
  ///
  /// Only version 0 is supported.

  late final BigInt _version;

  /// RSA modulus (n)

  late final BigInt modulus;

  /// RSA public exponent (e)

  late final BigInt _publicExponent;

  /// RSA private exponent (d)

  late final BigInt privateExponent;

  /// Prime 1 (p)

  late final BigInt prime1;

  /// Prime 2 (q)

  late final BigInt prime2;

  /// Exponent 1 = d mod (p-1)

  late final BigInt _exponent1;

  /// Exponent 2 = d mod (q-1)

  late final BigInt _exponent2;

  /// Coefficient = (inverse of q) mod p

  late final BigInt _coefficient;

  /// Source this was decoded from.
  ///
  /// Will always be set if this was created by the
  /// [Pkcs1RsaPrivateKey.decode] constructor, but otherwise could be null.

  final PvtTextSource? source;

  //================================================================
  // Methods

  //----------------------------------------------------------------
  /// Check values are consistent.
  ///
  /// Returns null if they are correct or an error message if they are not.

  String? _isCorrect() {
    if (_version != BigInt.zero) {
      throw FormatException('unexpected version $_version');
    }

    // Assuming prime1 and prime2 are really prime numbers...

    if (modulus != prime1 * prime2) {
      throw FormatException('invalid modulus'); // n = p * q
    }

    final phi = (prime1 - BigInt.one) * (prime2 - BigInt.one);

    if (_publicExponent != privateExponent.modInverse(phi)) {
      throw FormatException('invalid public exponent'); // e
    }

    if (privateExponent != _publicExponent.modInverse(phi)) {
      throw FormatException('invalid private exponent'); // d
    }

    if (_exponent1 != privateExponent % (prime1 - BigInt.one)) {
      throw FormatException('invalid exponent1');
    }

    if (_exponent2 != privateExponent % (prime2 - BigInt.one)) {
      throw FormatException('invalid exponent2');
    }

    if (_coefficient != prime2.modInverse(prime1)) {
      throw FormatException('invalid coefficient');
    }

    return null;
  }

  //----------------------------------------------------------------
  /// Encode as a sequence of bytes.

  @override
  Uint8List encode() => _asn1().encodedBytes;

  //----------------------------------------------------------------
  /// Encode as ASN.1.

  ASN1Object _asn1() => ASN1Sequence()
    ..add(ASN1Integer(_version))
    ..add(ASN1Integer(modulus))
    ..add(ASN1Integer(_publicExponent))
    ..add(ASN1Integer(privateExponent))
    ..add(ASN1Integer(prime1))
    ..add(ASN1Integer(prime2))
    ..add(ASN1Integer(_exponent1))
    ..add(ASN1Integer(_exponent2))
    ..add(ASN1Integer(_coefficient));
}
