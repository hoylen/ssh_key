part of ssh_key_txt;

//################################################################
/// Textual encoding
///
/// Implementation of the "textual encoding" defined by
/// [RFC 7468](https://tools.ietf.org/html/rfc7468). This format is a method
/// of representing binary data as text.
///
/// As RFC 7468 puts it, "_for reasons that basically boil down to
/// non-coordination or inattention, many PKIX, PKCS, and CMS libraries
/// implement a text-based encoding that is similar to -- but not identical
/// with --- PEM encoding. The RFC 7468 specifies a textual encoding format
/// that articulates the de facto rules that most implementations operate by._"
///
/// This encoding begins with a line that says "-----BEGIN label-----" and
/// ends with "-----END label-----" with base-64 encoded data between them.
///
/// Note: unlike the proprietary _OpenSSH public key format_
/// or the RFC 4716 'SSH Public Key File Format", this format does not
/// support a comment and/or headers.
///
/// ## Example
///
/// This example has "RSA PUBLIC KEY" as the label.
///
/// ```
/// -----BEGIN RSA PUBLIC KEY-----
/// MIIBCgKCAQEAyZ68gj6PPgga0C+1NbI2o/+ArLmh98fuKKH3wfHSsSQMOifg0ENO
/// ODUKDXdXDRepILtu2mjwvnr1mg48NP3b+Gxrp8od6Nz1pLrT6b01KbS1lsSn8V5l
/// EFK1+T5OXlxer+S0PUzaHlGwXRPdv0H7UqkBUd5xcFdpZvW0ARTk0CwRkrHI2uut
/// +nGiEH1fJWICcn4OCD2ZzbTGBBsTsxfSmQju6T7DIfuCbPBR49YKoPUYtaRcmSzS
/// JYA0bVANqmPhQ9xUQtKHwYSPFe1Q1VKC83x33na2os8LFGzGVb0rQthkqK8vM5jz
/// KfnpggTiElJr08KHgvpx4A1t7yg2rmtQHQIDAQAB
/// -----END RSA PUBLIC KEY-----
/// ```

class TextualEncoding implements PubTextEncoding {
  //================================================================
  // Constructors

  //----------------------------------------------------------------
  /// Creates a textual encoding from values.

  TextualEncoding(this.label, this.data) : source = null;

  //----------------------------------------------------------------
  /// Decode from text.
  ///
  /// Throws exception if there is no text encoding block found in the encoding.
  ///
  /// Data before the encapsulation boundary is permitted if [allowPreamble] is
  /// true (the default is false). That data can be
  /// identified by examining [TextualEncoding.source] in the result
  /// and comparing it any _offset_ that was provided.

  TextualEncoding.decode(String str,
      {int offset = 0, bool allowPreamble = false}) {
    // Set starting offset

    if (offset < 0) {
      throw ArgumentError.value(offset, 'offset', 'is negative');
    }
    var p = offset;

    // Skip whitespace

    while (p < str.length) {
      final ch = str[p];
      if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') {
        p++;
      } else {
        break;
      }
    }

    // Find the start of the pre-encapsulation header (i.e. the "-----BEGIN")
    //
    // Note: this implementation does not care if it is at the beginning of a
    // line or not.

    if (allowPreamble) {
      // Skip any text before the pre-encapsulation boundary
      p = str.indexOf(_boundaryBegin, p);
      if (p < 0) {
        throw KeyMissing('no Textual Encoding found');
      }
    } else {
      // Must start with the pre-encapsulation boundary (other than whitespace)
      if (!str.startsWith(_boundaryBegin, p)) {
        throw KeyMissing('no Textual Encoding');
      }
    }

    final offsetBegin = p; // record where the block starts

    p += _boundaryBegin.length; // skip over the "-----BEGIN "

    final labelBegin = p; // position just after the space in "-----BEGIN "

    // Skip to end of label (as indicated by "-----")

    var dashLength1 = 0;

    while (p < str.length) {
      final ch = str[p];
      if (ch == '-') {
        dashLength1++;
        if (dashLength1 == 5) {
          p++;
          break; // end of encapsulation boundary reached
        }
      } else if (ch == '\r' || ch == '\n') {
        p++;
        break; // end of line reached
      } else {
        dashLength1 = 0;
      }
      p++;
    }
    // Above loop finishes if "-----" encountered, end of line reached, or
    // end of encoding reached.

    if (dashLength1 != 5) {
      // Did not find the "-----" on the same line.
      throw KeyBad('malformed pre-encapsulation boundary');
    }

    final labelEnd = p - 5; // position where the "-----" starts
    final dataBegin = p; // position immediately after the "-----BEGIN ...-----"

    // Locate end of encapsulated data

    int? dataEnd;

    while (p < str.length) {
      if (str[p] == '-' &&
          p + _boundaryEnd.length < str.length &&
          str.substring(p, p + _boundaryEnd.length) == _boundaryEnd) {
        dataEnd = p;
        p += _boundaryEnd.length;
        break;
      }
      p++;
    }
    // Above loop finishes when "-----END " found or end of encoding.

    if (dataEnd == null) {
      // The "-----END " was not found in the encoding
      throw KeyBad('missing post-encapsulation boundary');
    }

    // Skip over the rest of the post-encapsulation boundary
    //
    // This implementation ignores the end-label (i.e. it does not need to match
    // the begin-label).

    var dashLength2 = 0;

    while (p < str.length) {
      final ch = str[p];
      if (ch == '-') {
        dashLength2++;
        if (dashLength2 == 5) {
          p++;
          break; // end of encapsulation boundary reached
        }
      } else if (ch == '\r' || ch == '\n') {
        p++;
        break; // end of line reached without encountering "-----"
      } else {
        dashLength2 = 0;
      }
      p++;
    }
    // Above loop finishes when "-----" is found on the same line, the end of
    // the line is reached, or the end of the encoding is reached.

    if (dashLength2 != 5) {
      // The "-----" was not found in the rest of the line
      throw KeyBad('malformed post-encapsulation boundary');
    }

    // Skip any CR, LF or CR-LF at end of encapsulation boundary

    if (p < str.length && str[p] == '\r') {
      p++;
    }
    if (p < str.length && str[p] == '\n') {
      p++;
    }

    // Decode the encoded text
    //
    // RFC 7468 specifies the encoded text uses the Base-64 encoding defined
    // in section 4 of [RFC 4648](https://tools.ietf.org/html/rfc4648#section-4)
    // (which uses "+" and "/" as the 62nd and 63rd characters, and "=" for
    // padding). The Dart Base64Codec implements Base-64 as defined by RFC 4648,
    // but the decoded does not allow invalid characters and requires the
    // correct padding.

    final encapsulatedData = StringBuffer();
    //final encapsulatedData = encoding.substring(dataBegin, dataEnd);
    for (var q = dataBegin; q < dataEnd; q++) {
      final ch = str.codeUnitAt(q);
      if ('A'.codeUnitAt(0) <= ch && ch <= 'Z'.codeUnitAt(0) ||
          'a'.codeUnitAt(0) <= ch && ch <= 'z'.codeUnitAt(0) ||
          '0'.codeUnitAt(0) <= ch && ch <= '9'.codeUnitAt(0) ||
          '+'.codeUnitAt(0) == ch ||
          '/'.codeUnitAt(0) == ch ||
          '='.codeUnitAt(0) == ch) {
        // valid character: use
        encapsulatedData.writeCharCode(ch);
      } else if (' \t\n\r'.codeUnits.contains(ch)) {
        // whitespace: ignore
      } else {
        throw KeyBad('unexpected character in base64 text: charcode=${ch}');
      }
    }
    try {
      data = base64.decode(encapsulatedData.toString()); // decode base64

      label = str.substring(labelBegin, labelEnd);
      source = TextSource._internal(str, offsetBegin, p);
    } on FormatException catch (e) {
        throw KeyBad('invalid encapsulated encoding: ${e.message}');
    }
  }

  //================================================================
  // Constants

  // Start of the pre-encapsulation boundary

  static const _boundaryBegin = '-----BEGIN '; // note: includes the space

  // Start of the post-encapsulation boundary

  static const _boundaryEnd = '-----END '; // note: includes the space

  //================================================================
  // Members

  /// The label for the textual encoding.
  ///
  /// RFC 7468 says, "_labels are formally case-sensitive, uppercase, and
  /// comprised of zero or more characters; they do not contain consecutive
  /// spaces or hyphen-minuses, nor do they contain spaces or hyphen-minuses at
  /// either end._"

  late String label;

  /// The encapsulated binary data.

  late Uint8List data;

  /// Source this was decoded from.
  ///
  /// Will always be set if this was created by the [TextualEncoding.decode]
  /// constructor, but otherwise is null.

  late TextSource? source;

  //================================================================
  // Methods
/*
  //----------------------------------------------------------------
  /// Retrieve the ASN.1 objects from the data.

  List<ASN1Object> get asn1 {
    try {
      var p = ASN1Parser(data);
      var objects = <ASN1Object>[];

      while (p.hasNext()) {
        objects.add(p.nextObject());
      }

      return objects;
    } on RangeError {
      throw BadEncoding('not valid ASN.1 BER');
    }
  }
*/
  //----------------------------------------------------------------
  /// Text encoding of the label and data.

  @override
  String encode() {
    final buf = StringBuffer('$_boundaryBegin$label-----\n'); // pre- boundary

    // Encapsulated text (base64 encode and split into lines)

    final b64 = base64.encode(data);

    var p = 0;
    while (p < b64.length) {
      final endPos = (p + 64 < b64.length) ? (p + 64) : b64.length;
      buf
        ..write(b64.substring(p, endPos))
        ..write('\n');
      p = endPos;
    }

    buf.write('$_boundaryEnd$label-----\n'); // post-encapsulation boundary

    return buf.toString();
  }
}
