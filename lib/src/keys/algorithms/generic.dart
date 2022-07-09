part of ssh_key;

//################################################################
/// Generic public key.
///
/// This is used to represent a public key where the details of the algorithm
/// are not known. All that is know about the public key is its [keyType] and
/// the binary [data] for it.
///
/// This class is used to represent public keys that have been parsed from the
/// OpenSSH Public Key format (i.e. the one line format) and this library
/// has not implemented support for that particular key-type.
///
/// Currently, this library has only impemented RSA keys, so this class will
/// be used for representing all other public keys in the _OpenSSH Public Key_
/// format. For example:
///
///     ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...
///     ssh-dss AAAAB3NzaC1kc3MAAACBAMhr
///     ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlz...
///
/// This class uses the [PublicKeyMixin] mixin for additional members
/// relating to encoding it in a file format. Namely, a collection of
/// [properties] and (if it was created by decoding text) [source].
///
/// The only  encoding format that is supported is the OpenSSH Public Key
/// format, using [encodeOpenSsh].
///
/// Methods for encoding it in different file formats are available. But
/// normally programs can just invoke the `encode` method (defined by the
/// [PublicKeyExt] extension on the Pointy Castle `PublicKey`), with a format
/// parameter -- that will cause one of these formatting methods to be invoked.

class GenericPublicKey with PublicKeyMixin implements pointy_castle.PublicKey {
  //================================================================
  // Constructors

  //----------------------------------------------------------------
  /// Constructor.

  GenericPublicKey(this.data);

  //----------------------------------------------------------------

  factory GenericPublicKey._fromOpenSSH(Uint8List bytes,
      {String? optionalComment, PubTextSource? source}) {
    assert(source == null || source.encoding == PubKeyEncoding.openSsh,
        'unexpected source of chunks: ${source.encoding}');

    _checkDataStartsWithKeyType(bytes);

    // Set optional comment

    final result = GenericPublicKey(bytes).._source = source;

    if (optionalComment != null) {
      result.properties.comment = optionalComment;
    }

    return result;
  }

  //================================================================
  // Members

  /// The data making up the public key.
  ///
  /// This must start with the keyType (represented as 32-bit length followed
  /// by the value) and then the data itself.

  Uint8List data;

  //================================================================

  //----------------------------------------------------------------
  // Type of key.

  String get keyType => BinaryRange(data).nextString();

  //----------------------------------------------------------------
  /// Encode an other public key in the OpenSSH Public Key format.
  ///
  /// Note: the OpenSSH format only supports one comment. Any additional
  /// comments and all other properties are not included in the encoding.
  ///
  /// Programs normally use `encode` method from the [PublicKeyExt] extension,
  /// with the appropriate format, which will invoke this method.

  String encodeOpenSsh() {
    _checkDataStartsWithKeyType(data);

    final encoding = OpenSshPublicKey(data, properties.comment);
    return encoding.encode();
  }

  //----------------------------------------------------------------
  // Checks if [bytes] starts with a key-type value.
  //
  // Throws [KeyBad] if it does not.

  static void _checkDataStartsWithKeyType(Uint8List bytes) {
    if (bytes.length < 6) {
      // minimum: 4-byte length, single character key-type, single byte body
      throw KeyBad('insufficient bytes for an OpenSSH Public Key');
    }
    final br = BinaryRange(bytes);
    String kt;
    try {
      kt = br.nextString();
    } on KeyBad {
      throw KeyBad('key-type missing from data');
    }

    if (kt.isEmpty) {
      throw KeyBad('invalid key-type: empty string');
    }

    if (br.isEmpty) {
      throw KeyBad('insufficient data: no bytes after the key-type');
    }
  }
}
