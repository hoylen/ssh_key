part of ssh_key_bin;

//################################################################
/// The "Subject Public Key Info" is defined by ASN.1 as a part
/// of X.509. It consists of an algorithm (identified by an OID
/// with optional parameters) and a bit string.
///
/// This is one of the formats that can be used by OpenSSH to store
/// public keys. It is text encoded with the label of "PUBLIC KEY"
/// (i.e. the pre encapsulation boundary is "-----BEGIN PUBLIC KEY-----").
/// OpenSSH incorrectly and confusingly refers to this format as "PKCS#8".
/// Real PKCS #8 is a format for private keys, not public keys, and
/// does not specify this format. To avoid further confusion, this
/// format will be referred to as the **Subject Public Key Info**
/// format, or **SPKI** for short.
///
/// This format is used in conjunction with the
/// RFC 7468 textual encoding (sometimes imprecisely referred to as "PEM").
///
/// The _SubjectPublicKeyInfo_ is defined in X.509: section 4.1 of
/// [RFC 2459](https://tools.ietf.org/html/rfc2459#section-4.1).
///
/// ```
/// SubjectPublicKeyInfo  ::=  SEQUENCE  {
///     algorithm            AlgorithmIdentifier,
///     subjectPublicKey     BIT STRING  }
/// ```
/// The _AlgorithmIdentifier_ is defined in section 4.1.1.2 of
/// [RFC 5280](https://tools.ietf.org/html/rfc5280#section-4.1.1.2)
///
/// ```
/// AlgorithmIdentifier  ::=  SEQUENCE  {
///     algorithm               OBJECT IDENTIFIER,
///     parameters              ANY DEFINED BY algorithm OPTIONAL  }
/// ```
///
/// The bit string contents of the _subjectPublicKey_ depend on the algorithm
/// used, and are defined in
/// [RFC 3279](https://tools.ietf.org/html/rfc3279#section-2.3).
///
/// Note: this class decodes from, and encodes to, binary data. That binary
/// data is usually decoded from text, or encoded to text, using
/// [RFC 7468](https://tools.ietf.org/html/rfc7468) Textual Encoding,
/// which is implemented by [TextualEncoding].

class SubjectPublicKeyInfo implements BinaryFormat {
  //================================================================
  // Constructors

  //----------------------------------------------------------------
  /// Constructor

  SubjectPublicKeyInfo(this.algorithmOid, this.algorithmParameters, this.data,
      [this.source]);

  //----------------------------------------------------------------
  /// Decode from a sequence of bytes.

  SubjectPublicKeyInfo.decode(Uint8List bytes, {this.source}) {
    String msg;

    try {
      // Parse the bytes as ASN.1

      List<ASN1Object> objects;

      try {
        objects = _asn1parseAll(bytes);
      } catch (e) {
        throw _SpkiMsg('bad ASN.1 encoding: $e');
      }

      // There must be only one top-level object

      if (objects.isEmpty) {
        throw _SpkiMsg(
            'no top-level objects (expecting 1, got ${objects.length})');
      }
      if (objects.length != 1) {
        throw _SpkiMsg(
            'too many top-level objects (expecting 1, got ${objects.length})');
      }

      // The top-level object must be a sequence of two items

      if (objects.first is! ASN1Sequence) {
        throw _SpkiMsg('top-level object is not a sequence');
      }
      // ignore: avoid_as
      final topSequence = objects.first as ASN1Sequence;

      if (topSequence.elements.length != 2) {
        throw _SpkiMsg('top-level sequence does not contain 2 items');
      }

      // 1. Algorithm information

      final a = topSequence.elements[0];

      if (a is! ASN1Sequence) {
        throw _SpkiMsg('algorithm-info is not a sequence');
      }
      // ignore: avoid_as
      final algorithmInfo = a as ASN1Sequence;

      if (algorithmInfo.elements.isEmpty) {
        throw _SpkiMsg('algorithm-info is empty');
      }

      // First algorithm parameter is an OID that identifies the algorithm

      final a1 = algorithmInfo.elements[0];
      if (a1 is! ASN1ObjectIdentifier) {
        throw _SpkiMsg('algorithm-info does not contain OID');
      }
      // ignore: avoid_as
      algorithmOid = (a1 as ASN1ObjectIdentifier).identifier;

      // Save rest of the algorithm parameters

      algorithmParameters = <ASN1Object>[];

      for (var i = 1; i < algorithmInfo.elements.length; i++) {
        algorithmParameters.add(algorithmInfo.elements[i]);
      }

      // 2. The data

      final bits = topSequence.elements[1];

      if (bits is! ASN1BitString) {
        throw _SpkiMsg('publicKey is not a bit string: ${bits.runtimeType}');
      }
      // ignore: avoid_as
      data = Uint8List.fromList((bits as ASN1BitString).stringValue);

      return; // success
    } on _SpkiMsg catch (e) {
      msg = e.message;
    } catch (e) {
      msg = 'unexpected: $e';
    }

    assert(msg != null);
    throw KeyBad('invalid public key: $msg');
  }

  //================================================================
  // Members

  /// Object Identifier (OID) that identifies the algorithm.

  String algorithmOid;

  /// Additional parameters for the algorithm.

  List<ASN1Object> algorithmParameters = [];

  /// Binary data containing the public key

  Uint8List data;

  /// Source this was decoded from.
  ///
  /// Will always be set if this was created by the
  /// [SubjectPublicKeyInfo.decode] constructor, but otherwise could be null.

  final PubTextSource source;

  //================================================================
  // Methods

  //----------------------------------------------------------------
  /// Encode as a sequence of bytes.
  ///
  /// These bytes are the DER encoding of the _Subject Public Key Info_.

  @override
  Uint8List encode() => _asn1().encodedBytes;

  //----------------------------------------------------------------
  /// Encode as ASN.1.

  ASN1Object _asn1() {
    // AlgorithmIdentifier

    final ai = ASN1Sequence()
      ..add(ASN1ObjectIdentifier.fromComponentString(algorithmOid));
    for (final param in algorithmParameters) {
      assert(param != null);
      ai.add(param);
    }

    // SubjectPublicKeyInfo

    return ASN1Sequence()..add(ai)..add(ASN1BitString(data));
  }
}

//################################################################
/// Internal exception used by the [SubjectPublicKeyInfo.decode] method.

class _SpkiMsg implements Exception {
  _SpkiMsg(this.message);
  String message;
}
