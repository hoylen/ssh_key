part of ssh_key_bin;

//################################################################
/// PKCS #1 version 2.0 representation of an RSA public key.
///
/// This class can be used to:
///
/// - Decode a sequence of bytes into the parameters for an RSA public key
///   using the [decode] constructor; or
/// - Encode the parameters for an RSA public key into a sequence of bytes
///   using the [encode] method.
///
/// The RSA public key parameters are the [modulus] and the public [exponent].
///
/// ## Format
///
/// This binary format is defined in
/// [RFC 2437](https://datatracker.ietf.org/doc/html/rfc2437#section-11.1.1)
/// _PKCS #1: RSA Cryptography Specifications, Version 2.0_
/// by this ASN.1 type:
///
/// ```
/// RSAPublicKey ::= SEQUENCE {
///   modulus           INTEGER,  -- n
///   publicExponent    INTEGER   -- e
/// }
/// ```
///
/// Where:
///
/// - modulus is the RSA modulus n.
/// - publicExponent is the RSA public exponent e.
///
/// The ASN.1 type is identical in PKCS #1 version 1.5, PKCS #1 version 2.1 and
/// PKCS #1 version 2.2.
///
/// PKCS #1 version 2.0 is referenced, because that is the version
/// implemented by [Pkcs1RsaPrivateKey].

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
            'ASN.1 encoding has wrong number of objects (expecting 1, got ${objects.length})');
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
          // Success

          modulus = n.valueAsBigInteger;
          exponent = e.valueAsBigInteger;
          return; // success
        } else {
          throw KeyBad('n and/or e are not ASN.1 Integers');
        }
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

  late final BigInt modulus;

  /// RSA exponent

  late final BigInt exponent;

  /// Source this was decoded from.
  ///
  /// Will always be set if this was created by the
  /// [Pkcs1RsaPublicKey.decode] constructor, but otherwise could be null.

  final PubTextSource? source;

  //================================================================
  // Methods

  //----------------------------------------------------------------
  /// Encode as a sequence of bytes.

  @override
  Uint8List encode() => _asn1().encodedBytes;

  //----------------------------------------------------------------
  /// Encode as ASN.1.

  ASN1Object _asn1() => ASN1Sequence()
    ..add(ASN1Integer(modulus))
    ..add(ASN1Integer(exponent));
}

//################################################################
/// Internal exception used by the [Pkcs1RsaPublicKey.decode] method.

class _Pkcs1Msg implements Exception {
  _Pkcs1Msg(this.message);
  String message;
}
