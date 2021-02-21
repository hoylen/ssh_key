part of ssh_key;

//################################################################
/// Common members for public keys that are enhanced with encoding information.
///
/// The public key has a collection of [properties], which may be empty.
///
/// The [source] indicated the fragment of text the public key was decoded
/// from, if it was created by decoding a string.

mixin PublicKeyMixin {
  //================================================================
  // Members

  late PubTextSource? _source;

  //----------------------------------------------------------------
  /// Properties associated with the public key.
  ///
  /// If the public key was decoded from text, any comment/properties from the
  /// text will be stored here.
  ///
  /// If the public key is encoded into text, these properties will be encoded
  /// into the text if the format supports them. Note: only the SSH Public Key
  /// format fully supports properties. The other formats either only support
  /// at most one comment, or no properties at all.

  final properties = Properties();

  //================================================================
  // Methods

  //----------------------------------------------------------------
  /// Section of text the public key was decoded from and the format decoded.
  ///
  /// Null if the public key was not decoded from any text.

  PubTextSource? get source => _source;
}

//################################################################
/// Extension on the Pointy Castle `PublicKey` class.
///
/// Defines a method to encode the public key.

extension PublicKeyExt on pointy_castle.PublicKey {
  //================================================================
  /// Encode a public key as text.
  ///
  /// Produces a text representation of the public key using in the requested
  /// `format`.
  ///
  /// Note: information that cannot be represented by the format will not be
  /// included in the encoded text.

  String encode(PubKeyEncoding format) => _publicKeyEncode(this, format);
}

//----------------------------------------------------------------
/// Encode a public key as text.
///
/// Produces a text representation of the public key using in the requested
/// [format].
///
/// Note: information that cannot be represented by the format will not be
/// included in the encoded text.

String _publicKeyEncode(
    pointy_castle.PublicKey pcPubKey, PubKeyEncoding format) {
  if (pcPubKey is RSAPublicKeyWithInfo) {
    switch (format) {
      case PubKeyEncoding.openSsh:
        return pcPubKey.encodeOpenSsh();
      case PubKeyEncoding.sshPublicKey:
        return pcPubKey.encodeSshPublicKey();
      case PubKeyEncoding.pkcs1:
        return pcPubKey.encodePkcs1();
      case PubKeyEncoding.x509spki:
        return pcPubKey.encodeX509spki();
    }
  } else if (pcPubKey is pointy_castle.RSAPublicKey) {
    return _publicKeyEncode(
        RSAPublicKeyWithInfo.fromRSAPublicKey(pcPubKey), format);
  } else {
    throw KeyUnsupported('unsupported type: ${pcPubKey.runtimeType}');
  }
}

//================================================================
// Decode functions

//----------------------------------------------------------------
/// Decodes the first public key from text.
///
/// Whitespace before the public key is ignored. By default, any non-whitespace
/// preamble before the key is not allowed. To ignore non-whitespace preamble,
/// set [allowPreamble] to true. Note: not all formats allow preamble.
///
/// ### Result
///
/// Returns first public key in [str], starting at [offset] (or the
/// beginning of the string if no offset is provided).
///
/// Returns a Pointy Castle `PublicKey`, which is an abstract
/// class. The program should determine what the actual type is and then cast it
/// into that type. For example,
///
/// ```
/// final k = publicKeyDecode(str);
/// if (k is RSAPublicKeyWithInfo) {
///   final rsaKey = k as RSAPublicKeyWithInfo;
///   // use the public key
/// }
/// ```
///
/// The text before and after the public key can be identified by examining
/// the _source_ member in the result (after casting it into its actual type).
///
/// ### Exceptions
///
/// A [KeyMissing] is thrown if no public key is found.
///
/// A [KeyBad] is thrown if the private key is invalid.
///
/// A [KeyUnsupported] is thrown if the type of public key is not supported.
///
/// ### See also
///
/// This method decodes one public key. If multiple public keys are expected in
/// the string use the [publicKeyDecodeAll] method.

pointy_castle.PublicKey publicKeyDecode(String str,
    {int offset = 0, bool allowPreamble = false}) {
  if (offset < 0) {
    throw ArgumentError.value(offset, 'offset', 'is negative');
  }
  var p = offset;

  // Skip leading whitespace

  while (p < str.length) {
    final ch = str[p];
    if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r') {
      p++;
    } else {
      break;
    }
  }

  // Try OpenSSH format (since it is the only one that cannot skip preamble)

  if (str.startsWith('ssh-', p)) {
    // Assume it is OpenSSH format

    final openSsh = OpenSshPublicKey.decode(str, offset: p);

    // The comment (if any) is included as a header
    final headers = <SshPublicKeyHeader>[];

    final c = openSsh.comment;
    if (c != null) {
      headers.add(SshPublicKeyHeader(SshPublicKeyHeader.commentTag, c));
    }

    return _keyFromOpenSshChunksAndHeaders(
        openSsh.data, headers, openSsh.source);
  }

  // Fall through to try remaining formats
  // They all must start with four or five hyphens

  final fourHyphens = str.indexOf('----', p);
  if (0 <= fourHyphens) {
    p = fourHyphens;

    if (str.startsWith(SshPublicKey.beginMarker, p)) {
      // Assume it is the SSH Public Key File Format (RFC 4716)
      final spk =
          SshPublicKey.decode(str, offset: p, allowPreamble: allowPreamble);

      return _keyFromOpenSshChunksAndHeaders(
          spk.bytes, spk.headers, spk.source);
    }

    // Fall through to try Textual Encoding formats

    final block =
        TextualEncoding.decode(str, offset: p, allowPreamble: allowPreamble);

    if (block.label == 'RSA PUBLIC KEY') {
      // Data is PKCS #1 (which always an RSA public key)

      final pkcs1 = Pkcs1RsaPublicKey.decode(block.data,
          PubTextSource.setEncoding(block.source!, PubKeyEncoding.pkcs1));

      return _rsaFromPkcs1(pkcs1);
    } else if (block.label == 'PUBLIC KEY') {
      // Data is subjectPublicKeyInfo

      final spki = SubjectPublicKeyInfo.decode(block.data,
          source: PubTextSource.setEncoding(
              block.source!, PubKeyEncoding.x509spki));

      if (spki.algorithmOid == _rsaAlgorithmOid) {
        // RSA public key

        assert(spki.algorithmParameters.length == 1 &&
            spki.algorithmParameters.first is ASN1Null);

        final pkcs1 = Pkcs1RsaPublicKey.decode(spki.data, spki.source);

        return _rsaFromPkcs1(pkcs1);
      } else {
        throw KeyUnsupported('unsupported algorithm: ${spki.algorithmOid}');
      }
    } else {
      throw KeyUnsupported('unsupported label: ${block.label}');
    }
  }

  throw KeyMissing('no key found');
}

//----------------------------------------------------------------
/// Decode a public key from OpenSSH chunks of data.
///
///

pointy_castle.PublicKey _keyFromOpenSshChunksAndHeaders(Uint8List bytes,
    Iterable<SshPublicKeyHeader> headers, PubTextSource? source) {
  RSAPublicKeyWithInfo result;

  final keyType = BinaryRange(bytes).nextString();

  switch (keyType) {
    case _rsaKeyType:
      result = _rsaPublicFromOpenSSH(bytes, source: source);
      break;
    // case KeyPublicDsa.keyType:
    //   result = KeyPublicDsa._fromBinaryChunks(chunks, source);
    //   break;
    default:
      throw KeyUnsupported('unsupported key-type: $keyType');
  }

  // Set properties from the headers

  for (final hdr in headers) {
    var value = hdr.value;
    if (hdr.tag.toLowerCase() == SshPublicKeyHeader.commentTag &&
        value.startsWith('"') &&
        value.endsWith('"') &&
        2 <= value.length) {
      // Remove quotation marks as recommended by section 3.3.2 of RFC 4716
      value = value.substring(1, value.length - 1);
    }

    result.properties.add(hdr.tag, value);
  }

  return result;
}

//----------------------------------------------------------------
/// Decodes multiple public keys from text.
///
/// This function can be used to decode the OpenSSH _authorized_keys_
/// file, which contains multiple public keys.
///
/// Returns all the public keys in [str], starting at [offset] (or the
/// beginning of the string if no offset is provided). If no public keys are
/// found, an empty list is returned. As with _publicKeyDecode_ the list
/// contains instances of Pointy Castle `PublicKey`, whose type can be examined
/// and then up-casted.
///
/// This method just keeps invoking the [publicKeyDecode] method until no more
/// keys are found in the string. Each invocation starts parsing immediately
/// after where the previous public key was found.

List<pointy_castle.PublicKey> publicKeyDecodeAll(String str, {int offset = 0}) {
  final results = <pointy_castle.PublicKey>[];

  if (offset < 0) {
    throw ArgumentError.value(offset, 'offset', 'is negative');
  }
  var pos = offset;

// Keep trying to decode a text encoding until no more found

  while (pos < str.length) {
    try {
      final item = publicKeyDecode(str, offset: pos);
      results.add(item);
      if (item is RSAPublicKeyWithInfo) {
        pos = item.source!.end + 1;
      } else {
        throw StateError('publicKeyDecode returned unexpected type');
      }
    } catch (e) {
      rethrow;
    }
  }

  return results;
}
