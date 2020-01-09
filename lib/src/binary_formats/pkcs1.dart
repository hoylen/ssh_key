part of ssh_key_bin;

//################################################################
/// PKCS #1 representation of an RSA public key.
///
/// Its encoding is defined in section 11.1.1 of
/// [RFC 2437](https://tools.ietf.org/html/rfc2437#section-11.1.1), which
/// has been obsoleted by
/// [RFC 3447](https://tools.ietf.org/html/rfc3447#appendix-A.1.1).
///
/// ```
/// RSAPublicKey ::= SEQUENCE {
///     modulus           INTEGER,  -- n
///     publicExponent    INTEGER   -- e
/// }
/// ```

class Pkcs1RsaPublicKey implements BinaryFormat {
  //================================================================
  // Constructors

  //----------------------------------------------------------------
  /// Constructor.

  Pkcs1RsaPublicKey(this.modulus, this.exponent, [this.source]);

  //----------------------------------------------------------------
  /// Decode from a sequence of bytes.

  Pkcs1RsaPublicKey.decode(Uint8List data, this.source) {
    String msg;

    try {
      List<ASN1Object> objects;

      try {
        objects = _asn1parseAll(data);
      } catch (e) {
        throw _Pkcs1Msg('bad ASN.1 encoding: $e');
      }

      if (objects.length != 1) {
        throw _Pkcs1Msg(
            'PKCS#1 has wrong number of objects (expecting 1, got ${objects.length})');
      }

      final topSequence = objects.first;
      if (topSequence is ASN1Sequence) {
        if (topSequence.elements.length != 2) {
          throw _Pkcs1Msg(
              'ASN.1 sequence wrong length (expecting 2, got ${topSequence.elements.length})');
        }

        final n = topSequence.elements[0];
        final e = topSequence.elements[1];
        if (n is ASN1Integer && e is ASN1Integer) {
          modulus = n.valueAsBigInteger;
          exponent = e.valueAsBigInteger;
        } else {
          throw KeyBad('n and/or e are not ASN.1 Integers');
        }

        return; // success
      } else {
        throw _Pkcs1Msg('DER is not a sequence');
      }
    } on _Pkcs1Msg catch (e) {
      msg = e.message;
    } catch (e) {
      msg = 'unexpected: $e';
    }

    throw KeyBad('invalid PKCS #1 public key: $msg');
  }

  //================================================================
  // Members

  /// RSA modulus

  BigInt modulus;

  /// RSA exponent

  BigInt exponent;

  /// Source this was decoded from.
  ///
  /// Will always be set if this was created by the
  /// [Pkcs1RsaPublicKey.decode] constructor, but otherwise could be null.

  PubTextSource source;

  //================================================================
  // Methods

  //----------------------------------------------------------------
  /// Encode as a sequence of bytes.

  @override
  Uint8List encode() => _asn1().encodedBytes;

  //----------------------------------------------------------------
  /// Encode as ASN.1.

  ASN1Object _asn1() =>
      ASN1Sequence()..add(ASN1Integer(modulus))..add(ASN1Integer(exponent));
}

//################################################################
/// Internal exception used by the [Pkcs1RsaPublicKey.decode] method.

class _Pkcs1Msg implements Exception {
  _Pkcs1Msg(this.message);
  String message;
}

//################################################################
/// https://tools.ietf.org/html/rfc2437#section-11.1.2
/*
class Pkcs1PrivateKey implements BinaryFormat {

  //================================================================
  // Methods

  //----------------------------------------------------------------
  /// Encode as a sequence of bytes.

  @override
  Uint8List encode() => throw UnimplementedError();

}

 */
