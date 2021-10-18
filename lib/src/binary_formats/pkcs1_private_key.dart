part of ssh_key_bin;

//################################################################
/// PKCS #1 representation of an RSA private key.
///
/// https://tools.ietf.org/html/rfc2437#section-11.1.2

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

    try {
      check(); // may fail if parameters were inconsistent
    } on FormatException catch (e) {
      throw ArgumentError(e.message);
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
        throw _Pkcs1Msg(
            'ASN.1 encoding has incorrect number of objects (expecting 1, got ${objects.length})');
      }

      final topSequence = objects.first;
      if (topSequence is ASN1Sequence) {
        const _numberOfIntegers = 9;

        // From <https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.1.2>
        //
        // RSAPrivateKey ::= SEQUENCE {
        //   version           Version,
        //   modulus           INTEGER,  -- n
        //   publicExponent    INTEGER,  -- e
        //   privateExponent   INTEGER,  -- d
        //   prime1            INTEGER,  -- p
        //   prime2            INTEGER,  -- q
        //   exponent1         INTEGER,  -- d mod (p-1)
        //   exponent2         INTEGER,  -- d mod (q-1)
        //   coefficient       INTEGER,  -- (inverse of q) mod p
        //   otherPrimeInfos   OtherPrimeInfos OPTIONAL
        // }
        //
        // otherPrimeInfos contains the information for the additional primes
        // r_3, ..., r_u, in order.  It SHALL be omitted if version is 0 and
        // SHALL contain at least one instance of OtherPrimeInfo if version
        // is 1.
        //
        // OtherPrimeInfos ::= SEQUENCE SIZE(1..MAX) OF OtherPrimeInfo
        //
        // OtherPrimeInfo ::= SEQUENCE {
        //   prime             INTEGER,  -- ri
        //   exponent          INTEGER,  -- di
        //   coefficient       INTEGER   -- ti
        // }

        if (topSequence.elements.length != _numberOfIntegers &&
            topSequence.elements.length != _numberOfIntegers + 1) {
          final expecting = '$_numberOfIntegers or ${_numberOfIntegers + 1}';
          throw _Pkcs1Msg('ASN.1 sequence has wrong length'
              ' (expecting $expecting, got ${topSequence.elements.length})');
        }

        // Check the mandatory members of the sequence are ASN.1 Integers

        final values = <BigInt>[];

        for (int x = 0; x < _numberOfIntegers; x++) {
          final n = topSequence.elements[x];
          if (n is ASN1Integer) {
            final value = n.valueAsBigInteger;
            if (value is BigInt) {
              values.add(value);
            } else {
              throw _Pkcs1Msg('ASN.1 sequence item $x does not have a value');
            }
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

        // Check the values are sane

        try {
          check();
        } on FormatException catch (e) {
          throw _Pkcs1Msg(e.message);
        }
        if (_numberOfIntegers < topSequence.elements.length) {
          // otherPrimeInfos is prohibited for version 0
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

  late BigInt _version;

  /// RSA modulus (n)

  late BigInt modulus;

  /// RSA public exponent (e)

  late BigInt _publicExponent;

  /// RSA private exponent (d)

  late BigInt privateExponent;

  /// Prime 1 (p)

  late BigInt prime1;

  /// Prime 2 (q)

  late BigInt prime2;

  /// Exponent 1 = d mod (p-1)

  late BigInt _exponent1;

  /// Exponent 2 = d mod (q-1)

  late BigInt _exponent2;

  /// Coefficient = (inverse of q) mod p

  late BigInt _coefficient;

  /// Source this was decoded from.
  ///
  /// Will always be set if this was created by the
  /// [Pkcs1RsaPrivateKey.decode] constructor, but otherwise could be null.

  final PvtTextSource? source;

  //================================================================
  // Methods

  //----------------------------------------------------------------
  /// Check values are consistent.

  void check() {
    if (_version != BigInt.zero) {
      throw FormatException('unexpected version $_version');
    }

    // Assuming prime1 and prime2 are really prime numbers...

    if (modulus != prime1 * prime2) {
      throw FormatException('invalid modulus'); // n = p * q
    }

    // TODO: calculate private exponent & public exponent from first principles

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
