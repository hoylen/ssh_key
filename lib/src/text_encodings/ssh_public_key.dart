part of ssh_key_txt;

//################################################################
/// SSH Public Key file format as defined by RFC 4716.
///
/// This format is sometimes referred to as the "SSH2 public key" format
/// or the "new OpenSSH public key format".
///
/// This encoding starts with "---- BEGIN SSH2 PUBLIC KEY ----".
///
/// defined by [RFC 4716](https://tools.ietf.org/html/rfc4716).
///
/// This encoding begins with a line that says
/// "---- BEGIN SSH2 PUBLIC KEY ----" and ends with
/// "---- END SSH2 PUBLIC KEY ----" with base-64 encoded data between them.
///
/// Note: this is different from the RFC 7468 textual encoding, which
/// has 5 hyphens and no spaces in its encapsulation boundaries.
///
/// This format supports arbitrary headers. he comment header-tag is one
/// of the defined header-tags.
///
/// ## Example
///
/// ```
/// ---- BEGIN SSH2 PUBLIC KEY ----
/// Comment: "2048-bit RSA, converted by user@example.com"
/// AAAAB3NzaC1yc2EAAAADAQABAAABAQDJnryCPo8+CBrQL7U1sjaj/4CsuaH3x+4ooffB8d
/// KxJAw6J+DQQ044NQoNd1cNF6kgu27aaPC+evWaDjw0/dv4bGunyh3o3PWkutPpvTUptLWW
/// xKfxXmUQUrX5Pk5eXF6v5LQ9TNoeUbBdE92/QftSqQFR3nFwV2lm9bQBFOTQLBGSscja66
/// 36caIQfV8lYgJyfg4IPZnNtMYEGxOzF9KZCO7pPsMh+4Js8FHj1gqg9Ri1pFyZLNIlgDRt
/// UA2qY+FD3FRC0ofBhI8V7VDVUoLzfHfedraizwsUbMZVvStC2GSory8zmPMp+emCBOISUm
/// vTwoeC+nHgDW3vKDaua1Ad
/// ---- END SSH2 PUBLIC KEY ----
/// ```

class SshPublicKey implements PubTextEncoding {
  //================================================================
  // Constructors

  //----------------------------------------------------------------
  /// Default constructor.

  SshPublicKey(this.headers, this.bytes) : source = null;

  //----------------------------------------------------------------
  /// Decode from text.
  ///
  /// Throws exception if there is no text encoding block found in the encoding.
  ///
  /// Data before the encapsulation boundary is permitted. That data can be
  /// identified by examining the [SshPublicKey.source] in the result
  /// and comparing it any _offset_ that was provided.

  SshPublicKey.decode(String str, {int offset = 0, bool allowPreamble = true}) {
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
      p = str.indexOf(beginMarker, p);
      if (p < 0) {
        throw KeyBad('no RFC 7468 encoding found');
      }
    } else {
      if (!str.startsWith(beginMarker, p)) {
        throw KeyBad('no RFC 7468 encoding');
      }
    }

    final offsetBegin = p; // record where the block starts

    // skip over the begin marker and the CR, LF or CR-LF after it

    p += beginMarker.length;

    if (p < str.length && str[p] == '\r') {
      p++;
    }
    if (p < str.length && str[p] == '\n') {
      p++;
    }

    // Decode the headers (if any)

    final hdr = _decodeHeaders(str, p);
    headers = hdr.item1;

    p = hdr.item2;

    // Find end of encoding

    final dataBegin = p;

    final dataEnd = str.indexOf(_endMarker, p);
    if (dataEnd < 0) {
      throw KeyBad('missing end marker');
    }

    // Skip end marker and any CR, LF or CR-LF after it

    p = dataEnd + _endMarker.length;

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
        encapsulatedData.writeCharCode(ch);
      }
    }

    source = PubTextSource(str, offsetBegin, p, PubKeyEncoding.sshPublicKey);

    try {
      bytes = base64.decode(encapsulatedData.toString());
      if (bytes.isEmpty) {
        throw KeyBad('no data');
      }
    } on FormatException catch (e) {
      if (e.message == 'Invalid length, must be multiple of four') {
        throw KeyBad('incomplete encapsulated data');
      } else {
        throw KeyBad('unexpected: ${e.message}');
      }
    }
  }

  //================================================================
  // Constants

  /// Begin marker
  static const beginMarker = '---- BEGIN SSH2 PUBLIC KEY ----';

  /// End marker
  static const _endMarker = '---- END SSH2 PUBLIC KEY ----';

  //================================================================
  // Members

  /// The headers as a list of (header-tag, header-value) pairs.
  ///
  /// Since the header-tags are case-insensitive. The lower-case values are
  /// stored in this list.

  late List<SshPublicKeyHeader> headers;

  /// The decoded bytes
  late Uint8List bytes;

  /// The text the key was decoded from
  ///
  /// This is set if it was creatd by [SshPublicKey.decode]. Otherwise, it is
  /// null.

  late PubTextSource? source;

  //================================================================
  // Methods

  //----------------------------------------------------------------
  // Encode to text.

  @override
  String encode({bool doNotQuoteComments = false}) {
    final buf = StringBuffer('$beginMarker\n');

    // Headers

    for (final h in headers) {
      var value = h.value;

      // Remove line breaks, the encoding does not support values with them
      value = value.replaceAll('\r', ' ').replaceAll('\n', ' ');

      if (!doNotQuoteComments) {
        // RFC 4716 says:
        // Currently, common practice is to quote the Header-value of the
        //   Comment by prefixing and suffixing it with '"' characters, and some
        //   existing implementations fail if these quotation marks are omitted.
        //
        //   Compliant implementations MUST function correctly if the quotation
        //   marks are omitted.
        //
        //   Implementations MAY include the quotation marks.  If the first and
        //   last characters of the Header-value are matching quotation marks,
        //   implementations SHOULD remove them before using the value.

        if (h.tag.toLowerCase() == SshPublicKeyHeader.commentTag) {
          value = '"$value"';
        }
      }

      final str = '${h.tag}: $value';

      var p = 0;
      while (p < str.length) {
        int endPos;
        if ((p + 72 < str.length)) {
          // continuation line
          endPos = p + 71;
          buf
            ..write(str.substring(p, endPos))
            ..write('\\\n');
        } else {
          // final line
          endPos = str.length;
          buf
            ..write(str.substring(p, endPos))
            ..write('\n');
        }
        p = endPos;
      }
    }
    // Encapsulated text

    final b64 = base64.encode(bytes);
    var p = 0;
    while (p < b64.length) {
      final endPos = (p + 72 < b64.length) ? (p + 72) : b64.length;
      buf
        ..write(b64.substring(p, endPos))
        ..write('\n');
      p = endPos;
    }

    // End marker

    buf.write('$_endMarker\n');

    return buf.toString();
  }

  //----------------
  /// Decode all headers.
  ///
  /// Returns the position after the new-line at the end of the last header
  /// line.

  static Tuple2<List<SshPublicKeyHeader>, int> _decodeHeaders(
      String content, int start) {
    // Note: keys are case insensitive
    final headers = <SshPublicKeyHeader>[];

    var lineStart = start;
    var p = lineStart;

    while (p < content.length && (content[p] == ' ' || content[p] == '\t')) {
      p++; // Skip leading whitespace on the line
    }
    var tagStart = p;

    while (p < content.length) {
      final ch = content[p];
      if (ch == ':') {
        if (tagStart == p) {
          throw KeyBad('header-tag missing');
        }

        final tag = content.substring(tagStart, p);
        if (64 < tag.length) {
          throw KeyBad('header-tag too long');
        }

        p++; // skip over the colon

        if (p < content.length && content[p] == ' ') {
          p++; // skip over spaces after the colon
          // Note: exactly one space is mandatory in RFC 4716, but this
          // implementation is more flexible and allows for it to be omitted.
        }

        final v = _decodeValue(content, p);
        if (1024 < v.item1.length) {
          throw KeyBad('header-value too long');
        }

        // Record header (note: any double quotes in comments are preserved)

        headers.add(SshPublicKeyHeader(tag, v.item1));

        // Continue parsing after the header

        p = v.item2;
        lineStart = p;

        while (
            p < content.length && (content[p] == ' ' || content[p] == '\t')) {
          p++; // Skip leading whitespace on the line
        }
        tagStart = p;
      } else if (ch == '\r' || ch == '\n') {
        // Reached end of line without encountering a colon: not a header line
        break;
      } else {
        p++;
      }
      /*
        var endPos = p;
        if (content[endPos] == '\n') {
          endPos++;
        }
        if (endPos < content.length && content[endPos] == '\r') {
          endPos++;
        }

        return Tuple4(start, p, endPos, colonPos);
      } else if (ch == ':') {
        colonPos = p;
      }

      p++;*/
    }

    // End of line or content reached without finding a colon (header line)
    return Tuple2(headers, lineStart);
  }

  //----------------
  /// Decode a single complete value.
  ///
  /// The [start] should be just after the colon on a header line. This method
  /// will keep parsing until the complete value (including all continuation
  /// lines) have been included.
  ///
  /// Returns the value and the offset after the new-line at the end of the
  /// value.

  static Tuple2<String, int> _decodeValue(String content, int start) {
    final value = StringBuffer();

    var p = start;
    var lineStart = p;
    var prevChar = '';
    while (p < content.length) {
      final ch = content[p];
      if (ch == '\r' || ch == '\n') {
        final valueEnd = p;

        p++; // skip over the LF if there is a CR-LF pair
        if (content[p - 1] == '\r' &&
            p < content.length &&
            content[p] == '\n') {
          p++; // skip over LF in CR-LF
        }

        if (prevChar != '\\') {
          value.write(content.substring(lineStart, valueEnd));
          break; // no continuation: end of value
        } else {
          // continuation on next line
          value.write(content.substring(lineStart, valueEnd - 1));
          lineStart = p;
        }
      } else {
        prevChar = ch;
        p++;
      }
    }

    return Tuple2(value.toString(), p);
  }
}

//################################################################
/// Represents a header in the SSH Public Key format.

class SshPublicKeyHeader {
  /// Constructor

  SshPublicKeyHeader(this.tag, this.value);

  //================================================================
  // Constants

  /// Tag name for the comment property.
  ///
  /// Used for the Comment header defined in
  /// [section 3.3.2 of RFC 4716](https://tools.ietf.org/html/rfc4716#section-3.3.2)
  /// and comments from the OpenSSH public key format.
  ///
  /// This value is guaranteed to be in lowercase.

  static const commentTag = 'comment';

  /// Tag name for the subject property.
  ///
  /// Used for the Subject header defined in
  /// [section 3.3.1 of RFC 4716](https://tools.ietf.org/html/rfc4716#section-3.3.1).
  ///
  /// This value is guaranteed to be in lowercase.

  static const subjectTag = 'subject';

  //================================================================
  // Members

  /// Header tag name
  final String tag;

  /// Header value
  final String value;
}
