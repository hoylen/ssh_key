part of ssh_key;

//################################################################
/// Class for internal use when decoding the PPK format.

class _EncodedPuttyPrivateParts {
  _EncodedPuttyPrivateParts(this.keyType, this.publicBytes, this.privateBytes,
      [this.comment]);
  String keyType;
  Uint8List publicBytes;
  Uint8List privateBytes;
  String? comment;
}

//################################################################
/// Common members for private keys that are enhanced with encoding information.
///
/// The private key may have a [comment].
///
/// The [source] indicated the fragment of text the private key was decoded
/// from, if it was created by decoding a string.

mixin PrivateKeyMixin {
  //================================================================
  // Members

  PvtTextSource? _source;

  //----------------------------------------------------------------
  /// Comment associated with the private key.
  ///
  /// Null if there is no comment.
  ///
  /// If the private key was decoded from text, any comment from the text will
  /// be stored here.
  ///
  /// If the private key is encoded into text, this comment will be encoded into
  /// the text if the format supports comments.

  String? comment;

  // Note: unlike public keys, private keys do not support arbitrary properties,
  // because none of the private key formats support anything other than a
  // single comment.
  //
  // The SSH Public Key (RFC 4726) format (where the need to support multiple
  // properties comes from) is not used for private keys.

  //----------------------------------------------------------------
  /// Section of text the private key was decoded from and the format decoded.
  ///
  /// Null if the private key was not decoded from any text.

  PvtTextSource? get source => _source;

  //  Uint8List dummyPrefix;
}

//################################################################
/// Extension on the Pointy Castle `PrivateKey` class.
///
/// Defines a method to encode the private key.

extension PrivateKeyExt on pointy_castle.PrivateKey {
  //----------------------------------------------------------------
  /// Encode a private key as text.
  ///
  /// Produces a text representation of the public key using in the requested
  /// `format`.
  ///
  /// Note: information that cannot be represented by the format will not be
  /// included in the encoded text.

  String encode(PvtKeyEncoding format) => _privateKeyEncode(this, format);
}

//================================================================
// Encode functions

//----------------------------------------------------------------
/// Encode a private key as text.
///
/// Produces a text representation of the public key using in the requested
/// [format].
///
/// Note: information that cannot be represented by the format will not be
/// included in the encoded text.

String _privateKeyEncode(pointy_castle.PrivateKey pvtKey, PvtKeyEncoding format,
    {String passphrase = ''}) {
  if (pvtKey is RSAPrivateKeyWithInfo) {
    // ssh_key RSAPrivateKeyWithInfo

    switch (format) {
      case PvtKeyEncoding.openSsh:
        return pvtKey.encodeOpenSshPrivateKey();
      case PvtKeyEncoding.puttyPrivateKey:
        return pvtKey.encodePuttyPrivateKey(passphrase);
    }
  } else if (pvtKey is pointy_castle.RSAPrivateKey) {
    // Pointy Castle RSAPrivateKey: upgrade it and encode that

    return _privateKeyEncode(
        RSAPrivateKeyWithInfo.fromRSAPrivateKey(pvtKey), format);
  } else {
    throw KeyUnsupported('unsupported type: ${pvtKey.runtimeType}');
  }
}

//################################################################
// Functions

//================================================================
// Decode functions

//----------------------------------------------------------------
/// Decodes the first private key from text.
///
/// Whitespace before the private key is ignored. By default, any non-whitespace
/// preamble before the key is not allowed. To ignore non-whitespace preamble,
/// set [allowPreamble] to true. Note: not all formats allow preamble.
///
/// ### Result
///
/// Returns first private key in [str], starting at [offset] (or the
/// beginning of the string if no offset is provided).
///
///
/// The text before and after the private key can be identified by examining
/// the _source_ member in the result (after casting it into its actual type).
///
/// ### Exceptions
///
/// A [KeyMissing] is thrown if no private key is found.
///
/// A [KeyBad] is thrown if the private key is invalid.
///
/// A [KeyUnsupported] is thrown if the type of private key is not supported.

pointy_castle.PrivateKey privateKeyDecode(String str,
    {int offset = 0, bool allowPreamble = false, String passphrase = ''}) {
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

  if (str.startsWith(PuttyPrivateKey.puttyKeyTypeTag, p)) {
    final ppk = PuttyPrivateKey.decode(str, offset: p);

    switch (ppk.keyType) {
      case 'ssh-rsa':
        break;
      default:
        throw KeyUnsupported('unsupported algorithm: ${ppk.keyType}');
    }

    return _rsaPrivateFromPPK(
        ppk.publicKeyBytes, ppk.privateKeyBytes, ppk.comment, ppk.source);

    // TODO

  } else if (str.startsWith('---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----')) {
    throw KeyUnsupported('SSH.com keys not implemented yet');
  } else {
    // Try Textual Encoding

    final block =
        TextualEncoding.decode(str, offset: p, allowPreamble: allowPreamble);

    if (block.label == 'OPENSSH PRIVATE KEY') {
      // OpenSSH Private Key (i.e. the new OpenSSH format)
      // Data is ... TODO

      final ospk = OpenSshPrivateKey.decode(block.data,
          source:
              PvtTextSource.setEncoding(block.source!, PvtKeyEncoding.openSsh));
      // TODO: use private key format!!!

      switch (ospk.privateKeyType) {
        case 'ssh-rsa':
          return _rsaPrivateFromOpenSSH(
              ospk.publicKeyBytes, ospk.privateKeyBytes, ospk.source);

        default:
          throw KeyUnsupported('unsupported algorithm: ${ospk.privateKeyType}');
      }
    } else if (block.label == 'RSA PRIVATE KEY') {
      // PKCS #1 Private Key (i.e. the original OpenSSH format)

      //print(_hexDump(block.data, name: 'PKCS #1 Private Key data'));
      print('PKCS #1 data length: ${block.data.length}');

      throw KeyUnsupported('Decoding PKCS #1 Private Key not implemented yet');
    } else {
      throw KeyUnsupported('unsupported label: ${block.label}');
    }
  }
}

// https://coolaj86.com/articles/the-openssh-private-key-format/
// https://coolaj86.com/articles/openssh-vs-openssl-key-formats/
