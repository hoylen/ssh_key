part of ssh_key_bin;

//################################################################

/// Decode the [bytes] into ASN.1 data.

List<ASN1Object> _asn1parseAll(Uint8List bytes) {
  try {
    final p = ASN1Parser(bytes);

    final objects = <ASN1Object>[];
    while (p.hasNext()) {
      objects.add(p.nextObject());
    }

    return objects;
    // ignore: avoid_catching_errors
  } on RangeError {
    throw KeyBad('not valid ASN.1 BER');
  }
}
