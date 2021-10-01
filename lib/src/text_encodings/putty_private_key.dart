part of ssh_key_txt;

//################################################################
/// Represents the PuTTY Private Key format.
///
///
/// ## Example
///
/// ```
/// PuTTY-User-Key-File-2: ssh-rsa
/// Encryption: none
/// Comment: someone@example.com
/// Public-Lines: 6
/// AAAAB3NzaC1yc2EAAAADAQABAAABAQDJnryCPo8+CBrQL7U1sjaj/4CsuaH3x+4o
/// offB8dKxJAw6J+DQQ044NQoNd1cNF6kgu27aaPC+evWaDjw0/dv4bGunyh3o3PWk
/// utPpvTUptLWWxKfxXmUQUrX5Pk5eXF6v5LQ9TNoeUbBdE92/QftSqQFR3nFwV2lm
/// 9bQBFOTQLBGSscja6636caIQfV8lYgJyfg4IPZnNtMYEGxOzF9KZCO7pPsMh+4Js
/// 8FHj1gqg9Ri1pFyZLNIlgDRtUA2qY+FD3FRC0ofBhI8V7VDVUoLzfHfedraizwsU
/// bMZVvStC2GSory8zmPMp+emCBOISUmvTwoeC+nHgDW3vKDaua1Ad
/// Private-Lines: 14
/// AAABAF9IgVYcMp3iPqm8oirqOiBvE2SNphnvhoH1aZ1ip2vH2W9ygTBrXn/5sPKE
/// P8OUNv2dFtppVbzvZzqTF6kDf/17X7VAM7plEkHzeUqxfHplSJwj/Cp5rdF1BULx
/// SyAVDzqZHwUJWNuTR4H1bYqBqEB8Vn9WXM32wX1DCPqp4Sjvk+80P9edf3+Y5IFC
/// VgQmbPUVM2GKzhBOe1FjroHnWwIWr/O7oZzBDZqzF4y0R0i8okqsCCDqSWkvM29A
/// 8syTYEV6VyUxVdfXTiApg3wYdWhB0VWpXJ4qbN1L3jGFawlQHUM/5tj3O+swjMrt
/// LTd5Y/2ce8si9MU03Qkvl4RzEhEAAACBAOVzVG2+no81XG1hOo5t3AQe9QrY0Sr8
/// vhZSZ6Wh9cTtEASc187D5kYXxyGxs0vO0RdC0XT1cLizGrnv8RHsqHw5Jq0yEnJg
/// pzbAs2MZAJAESQRlQbWpP4rFPDEgD1hd0ZB+5CgeY1qP7x7cku+D6tdAScr3WhQt
/// RND9CWhIyI9zAAAAgQDg8wbfjvuQMmqBVn+wS6NX7cCNj4RfhA5+f6+pZnvooVhq
/// Mh8IiD+JI1SdAUV18YzjAQmy3VeSQp3YImn54IdII3OW3m0BoWzq5tW4ZKPMYMaY
/// 7+ksbCDzEfxZUpyPjr3W4S3VQEWoL+A1LT9+VmitBGhs3myf4yxPVQEC7rCeLwAA
/// AIEA2lwJ3kfWf2HtBy93o+Pye9m1BHaGGr8RzpsfTHwlQv+4zw7HpY6P1l8gkgUV
/// yDNARZ0FYVsz9fs0iTacT3kqxYVvR4KlI1RbdOibb/k/pkzwbv4I2zn/UuIjP+TS
/// U2hkfvbMNLftTYn+6AxStBj52pMey3Ocdmfvp5RqUNoJqr4=
/// Private-MAC: 200f3733e416932e8f225d7a0a4212514a8a4879
/// ```

class PuttyPrivateKey implements PvtTextEncoding {
  //================================================================
  // Constructors

  //----------------------------------------------------------------
  /// Default constructor
  ///
  /// Create a Putty Private Key object. This is usually used when the program
  /// has a public-key pair and wants to export it in the PPK format.
  /// Use this constructor to create the object and then invoke [encode] on it.
  ///
  /// An optional [comment] can be provided.

  PuttyPrivateKey(
      this.keyType, this.encryption, this.publicKeyBytes, this.privateKeyBytes,
      [this.comment])
      : source = null;

  //----------------------------------------------------------------
  /// Decode from text
  ///
  /// Throws a FormatException if the string does not contain correctly encoded
  /// value. Any whitespace at the start of the string is skipped.

  PuttyPrivateKey.decode(String str, {int offset = 0}) {
    // The Putty Private Key format is documented in "sshpubk.c" from the
    // Putty source code.

    if (offset < 0) {
      throw ArgumentError.value(offset, 'offset', 'is negative');
    }

    source =
        PvtTextSource(str, offset, str.length, PvtKeyEncoding.puttyPrivateKey);

    // Split into lines

    final actualStr = (source!.begin == 0) ? str : str.substring(offset);
    final lines = const LineSplitter().convert(actualStr);

    // Parse the lines. Although the PPK format defines a strict order for
    // the lines, this parser will accept the lines in any order.

    String? _privateMAC;
    String? _keyType;
    String? _encryption;
    Uint8List? _publicKeyBytes;
    Uint8List? _privateKeyBytes;

    while (lines.isNotEmpty) {
      // Try to match a name: value line.
      //
      // Important: exactly one space is expected after the colon. This is very
      // significant for the comment, where spaces in the value (possibly at the
      // beginning, the end, or entirely made up of spaces) are significant.
      // The comment is included in the calculation of the Private-MAC, so every
      // character is significant, otherwise the HMAC will not match.

      final a = RegExp(r'^([\w_-]+): (.*)$').firstMatch(lines[0]);
      if (a == null) {
        if (RegExp(r'^\s*$').hasMatch(lines[0])) {
          lines.removeAt(0);
          continue; // skip blank lines
        } else {
          throw KeyBad('PPK: invalid format: ${lines[0]}');
        }
      }
      final name = a.group(1)!;
      final value = a.group(2)!;

      String? numBase64Lines;

      switch (name) {
        case puttyKeyTypeTag:
          _keyType = value;
          break;
        case 'Encryption':
          if (value != 'none' && value != 'aes256-cbc') {
            throw KeyUnsupported('PKK encryption: $value');
          }
          _encryption = value;
          break;
        case 'Comment':
          comment = value;
          break;
        case 'Public-Lines':
          numBase64Lines = value;
          break;
        case 'Private-Lines':
          numBase64Lines = value;
          break;
        case 'Private-MAC':
          _privateMAC = value;
          break;
        default:
          throw KeyBad('PPK tag unknown: $name');
      }

      lines.removeAt(0);

      if (numBase64Lines != null) {
        // Process indicated number of lines as base-64 encoded data

        int numLines;
        try {
          numLines = int.parse(numBase64Lines);
          if (numLines < 0) {
            throw KeyBad('PPK: $name: negative');
          }
        } on FormatException {
          throw KeyBad('PPK: $name: not integer');
        }

        final buf = StringBuffer();
        while (0 < numLines) {
          if (lines.isEmpty) {
            throw KeyBad('PPK: incomplete');
          }
          buf.write(lines[0]);
          lines.removeAt(0);
          numLines--;
        }

        final data = base64.decode(buf.toString());
        if (name == 'Public-Lines') {
          _publicKeyBytes = data;
        } else if (name == 'Private-Lines') {
          _privateKeyBytes = data;
        } else {
          assert(false);
        }
      }
    }

    if (_keyType == null) {
      throw KeyBad('PPK: missing standard tag');
    }
    if (_keyType != 'ssh-rsa') {
      throw KeyUnsupported('PPK key type: $_keyType');
    }
    keyType = _keyType;

    if (_encryption == null) {
      throw KeyBad('PKK: missing encryption tag');
    }
    encryption = _encryption;

    if (comment != null) {
      if (comment!.isEmpty) {
        // Comment is always present in PPK, even when its value is an empty
        // string. This implementation represents an emtpy comment with null,
        // so if it is translated to other formats (where the comment is optional)
        // empty comments will be omitted.
        comment = null;
      }
    } else {
      throw KeyBad('PPK: missing comment tag');
    }

    if (_publicKeyBytes != null) {
      publicKeyBytes = _publicKeyBytes;
    } else {
      throw KeyBad('PPK: missing Public-Lines');
    }

    if (_privateKeyBytes != null) {
      privateKeyBytes = _privateKeyBytes;
    } else {
      throw KeyBad('PPK: missing Private-Lines');
    }

    // Check the MAC

    if (_privateMAC == null) {
      throw KeyBad('PPK: missing Private-MAC');
    }

    final passphrase = ''; // TODO
    final calculatedMac = _calculatePrivateMAC(keyType, passphrase);

    if (_privateMAC != calculatedMac) {
      // print('Private-MAC: read="$_privateMAC" calculated="$calculatedMac"');
      throw KeyBad('PPK: key tampered with: Private-MAC does not match');
    }
  }
  //================================================================
  // Constants and static members

  /// First line.
  ///
  /// The first line must start with this, a colon, and the
  /// name of the algorithm.

  static const puttyKeyTypeTag = 'PuTTY-User-Key-File-2';

  //================================================================
  // Members

  /// Key-type
  late String keyType;

  /// Encryption method
  late String encryption;

  /// Comment
  late String? comment;

  /// Bytes in the public key lines
  late Uint8List publicKeyBytes;

  /// Bytes in the private key lines
  late Uint8List privateKeyBytes;

  /// Source text this PKK was decoded from
  late PvtTextSource? source;

  //================================================================
  // Methods

  //----------------------------------------------------------------
  /// Calculate the Private-Mac.
  ///
  /// This is used to calculate the Private-Mac, so its value can be compared
  /// to the read value when decoding. It is also used to to calculate its
  /// value when encoding.

  String _calculatePrivateMAC(String algorithm, String passphrase) {
    // The "Private-MAC" value is the hex representation of a HMAC-SHA-1 of
    //
    //    string  name of algorithm ("ssh-dss", "ssh-rsa")
    //    string  encryption type
    //    string  comment
    //    string  public-blob
    //    string  private-plaintext (the plaintext version of the
    //                               private part, including the final
    //                               padding)
    //
    // Important: the above, "string" means there is a 4-byte big-endian length
    // followed by the bytes that make up the value.
    //
    // The key to the MAC is itself a SHA-1 hash of:
    //
    //    data    "putty-private-key-file-mac-key"
    //    data    passphrase
    //
    // (An empty passphrase is used for unencrypted keys.)

    final k = 'putty-private-key-file-mac-key$passphrase';
    final macKey =
        pointy_castle.SHA1Digest().process(Uint8List.fromList(utf8.encode(k)));

    final macData = BinaryLengthValue.encode([
      BinaryLengthValue.fromString(algorithm),
      BinaryLengthValue.fromString(encryption),
      BinaryLengthValue.fromString(comment ?? ''),
      BinaryLengthValue(publicKeyBytes),
      BinaryLengthValue(privateKeyBytes)
    ]);

    // For HMAC SHA-1, the block length must be 64
    final hmac = pointy_castle.HMac(pointy_castle.SHA1Digest(), 64)
      ..init(pointy_castle.KeyParameter(macKey));

    final d = hmac.process(macData);

    // Return hexadecimal representation

    return _hex(d);
  }

  /// Convert a list of bytes into hexadecimal string representation.

  String _hex(Uint8List bytes) {
    final buf = StringBuffer();
    for (final b in bytes) {
      final s = b.toRadixString(16);
      buf.write('${(s.length == 1) ? '0' : ''}$s');
    }
    return buf.toString();
  }

  //----------------------------------------------------------------

  @override
  String encode(String passphrase) {
    final buf = StringBuffer();

    // The algorithm can be found in the public key data
    final algorithm = BinaryRange(publicKeyBytes).nextString();

    buf
      ..write('$puttyKeyTypeTag: $algorithm\n')
      ..write('Encryption: $encryption\n')
      ..write('Comment: ${comment ?? ''}\n');
    _encodePPKLines('Public-Lines', publicKeyBytes, buf);
    _encodePPKLines('Private-Lines', privateKeyBytes, buf);
    buf.write('Private-MAC: ${_calculatePrivateMAC(algorithm, passphrase)}\n');

    // Note: PuTTYgen always produces a Comment line, even when there is no
    // comment). When there is no comment, PuTTYgen still outputs a single space
    // after the colon. This implementation produces the same results.

    return buf.toString();
  }

  //----------------

  void _encodePPKLines(String tag, Uint8List data, StringBuffer buf) {
    const maxLineLength = 64;

    final t = base64.encode(data);

    var numLines = t.length ~/ maxLineLength;
    if (t.length % maxLineLength != 0) {
      numLines++;
    }

    buf.write('$tag: $numLines\n');

    var offset = 0;
    while (offset < t.length) {
      final line = (offset + maxLineLength < t.length)
          ? t.substring(offset, offset + maxLineLength)
          : t.substring(offset);
      buf
        ..write(line)
        ..write('\n');
      offset += maxLineLength;
    }
  }
}
