part of ssh_key_txt;

//################################################################
/// Represents the OpenSSH Public Key format.
///
/// This format supports a single optional comment, but no other properties.
///
/// The text encoding consists of a single line containing: the key-type,
/// base-64 encoded binary representation, and an optional comment.
///
/// The binary representation contains a number of chunks of data, depending on
/// the encryption algorithm. The first chunk is always a duplicate copy of the
/// key-type.
///
/// This class is used for the binary representation of both this
/// _OpenSSH public key format_ and the bit string inside of the _SSH Public Key
/// File Format_.
/// The [SshPublicKey] class implements the encoding and decoding of that
/// second format.
///
/// ## Example
///
/// ```
/// ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDJnryCPo8...a1Ad user@example.com
/// ```
///
/// This is a proprietary format. It is largely undocumented, except partially
/// in the "Authorized_keys file format" section of OpenSSH's
/// [sshd man page](https://man.openbsd.org/sshd.8).
///
/// This implementation does not support options. It will fail to decode lines
/// that contain public keys with options.

class OpenSshPublicKey implements PubTextEncoding {
  //================================================================
  // Constructors

  //----------------------------------------------------------------
  /// Construct an OpenSSH public key.
  ///
  /// The key is represented by the binary [data].
  ///
  /// An optional [comment] can be provided.
  ///
  /// If it was parsed from text, the source can be recorded by providing the
  /// [source], indicating the start of the key-type and the end of the
  /// comment (or the end of the base-64 encoded key, if there was no comment).

  OpenSshPublicKey(this.data, [this.comment, this.source]);

  //----------------------------------------------------------------
  /// Decode from text
  ///
  /// The [str] must consist of a line containing:
  /// - key type
  /// - single space
  /// - base-64 encoded OpenSSH format key
  /// - optional: single space followed by a comment
  ///
  /// This decoder is less strict and will accept multiple whitespaces where
  /// a single space is expected. It will also ignore any white space and blank
  /// lines before the key-type (i.e. the key-type does not have to be at the
  /// beginning of the line).
  ///
  /// https://tools.ietf.org/html/rfc4253#section-6.6
  ///
  /// Throws a FormatException if the string does not contain correctly encoded
  /// value. Any whitespace at the start of the string is skipped.

  OpenSshPublicKey.decode(String str, {int offset = 0}) {
    // Skip the key type

    if (str.isEmpty) {
      throw KeyMissing('OpenSSH Public Key: string is empty');
    }

    var p = offset;

    // Skip leading whitespace and blank lines

    while (p < str.length) {
      final ch = str[p];
      if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') {
        p++;
      } else {
        break;
      }
    }

    final keyTypeStart = p;
    int? algorithmNameEnd;

    while (p < str.length) {
      final ch = str[p];
      if (ch == ' ') {
        if (p != keyTypeStart + 1) {
          algorithmNameEnd = p;
          p++;
          break;
        } else {
          break;
        }
      } else {
        p++;
      }
    }

    if (algorithmNameEnd == null) {
      throw KeyBad('OpenSSH Public Key: key-type missing');
    }

    final keyType = str.substring(keyTypeStart, algorithmNameEnd);

    // Find start of PEM data (by skipping all whitespace)

    while (p < str.length && (str[p] == ' ' || str[p] == '\t')) {
      p++;
    }

    final pemStart = p;

    // Find end of PEM encoded data

    while (p < str.length &&
        (str[p] != ' ' && str[p] != '\t' && str[p] != '\r' && str[p] != '\n')) {
      p++;
    }

    if (pemStart == p) {
      throw KeyBad('OpenSSH Public Key: base64 missing');
    }

    final pemEnd = p;

    // Parse optional comment

    if (p == str.length) {
      // End of string string
      comment = null; // no comment

    } else if (str[p] == '\r' || str[p] == '\n') {
      // End of the line
      comment = null; // no comment

    } else if (str[p] == ' ') {
      // There is a space after the base64, so the rest of the line is a comment

      p++; // skip over the space

      final commentStart = p;

      // Find end of comment (which is terminated by the end-of-line or string)

      while (p < str.length && (str[p] != '\r' && str[p] != '\n')) {
        p++;
      }

      comment = str.substring(commentStart, p);
    } else {
      throw KeyBad('OpenSSH Public Key: base64 terminated incorrectly');
    }

    // Skip over any CR, LF or CR-LF

    if (p < str.length && str[p] == '\r') {
      p++;
    }
    if (p < str.length && str[p] == '\n') {
      p++;
    }

    // Source

    source = PubTextSource(str, keyTypeStart, p, PubKeyEncoding.openSsh);

    // Decode the base-64 text

    try {
      data = base64.decode(str.substring(pemStart, pemEnd));

      final chunks = BinaryRange(data);

      // The first chunk of data is the key-type and should be the same as the
      // text key-type at the beginning of the line

      if (BinaryRange.copy(chunks).nextString() != keyType) {
        throw KeyBad('OpenSSH Public Key: algorithm name mismatch');
      }
    } on FormatException catch (e) {
      if (e.message == 'Invalid length, must be multiple of four') {
        throw KeyBad('OpenSSH Public Key: base64 invalid');
      } else {
        throw KeyBad('OpenSSH Public Key: ${e.message}');
      }
    }
  }

  //================================================================
  // Members

  /// Binary data representing the public key.

  late Uint8List data;

  /// Comment
  ///
  /// Null if there is no comment.

  String? comment;

  /// Source text the OpenSSH public key was parsed from.
  ///
  /// Indicates the start of the key-type and the end of the comment (or the
  /// end of the base-64 encoded key, if there was no comment).
  ///
  /// Null if it wasn't parsed from text.

  PubTextSource? source;

  //================================================================

  /// Encode as text.
  ///
  /// Produced the single-line representation.
  ///
  /// The optional comment is included only if its has a value and that value
  /// is not a blank or empty string.

  @override
  String encode() {
    // Key-type is the same as the first chunk

    final keyType = BinaryRange(data).nextString();

    // Only include the comment if its value is not empty.

    var spacePlusComment = '';

    if (comment != null) {
      // There is a comment.
      // Note: all spaces in the comment are preserved.
      var s = comment!;
      s = s.replaceAll('\r', ' '); // disallow multi-line comments
      s = s.replaceAll('\n', ' ');

      if (s.isNotEmpty) {
        spacePlusComment = ' $s'; // add a space in front of the comment
      }
    }

    // Produce the one-line encoding

    return '$keyType ${base64.encode(data)}$spacePlusComment\n';
  }
}
