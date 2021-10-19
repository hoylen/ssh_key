part of ssh_key_bin;

//################################################################
/// Represents the OpenSSH private key format.
///
/// ## Format
///
/// This is proprietary format that is not been officially documented.
///
/// Unofficial documentation can be found in a blog post on
/// [The OpenSSH Private Key Format](https://coolaj86.com/articles/the-openssh-private-key-format/).
/// by A. J. O'Neal, which says the format is:
///
/// ```text
/// "openssh-key-v1"0x00    # NULL-terminated "Auth Magic" string
/// 32-bit length, "none"   # ciphername length and string
/// 32-bit length, "none"   # kdfname length and string
/// 32-bit length, nil      # kdf (0 length, no kdf)
/// 32-bit 0x01             # number of keys, hard-coded to 1 (no length)
/// 32-bit length, sshpub   # public key in ssh format
///     32-bit length, keytype
///     32-bit length, pub0
///     32-bit length, pub1
/// 32-bit length for rnd+prv+comment+pad
///     64-bit dummy checksum?  # a random 32-bit int, repeated
///     32-bit length, keytype  # the private key (including public)
///     32-bit length, pub0     # Public Key parts
///     32-bit length, pub1
///     32-bit length, prv0     # Private Key parts
///     ...                     # (number varies by type)
///     32-bit length, comment  # comment string
///     padding bytes 0x010203  # pad to blocksize (see notes below)
/// ```
///
/// More details are in the blog post.
///
/// The most correct source of information on this format is the
/// [OpenSSH source code](https://www.openssh.com/ftp.html#http)
/// or from the
/// [Portable OpenSSH](https://github.com/openssh/openssh-portable/blob/master/sshkey.c)
/// fork of it.

class OpenSshPrivateKey implements BinaryFormat {
  //================================================================
  // Constructors

  //----------------------------------------------------------------
  // Default constructor

  /// Default constructor

  OpenSshPrivateKey(this.cipherName, this.kdfName, this.kdf,
      this.publicKeyBytes, this.privateKeyBytes,
      [this.source]);

  //----------------------------------------------------------------
  /// Decode from a sequence of bytes.

  factory OpenSshPrivateKey.decode(Uint8List bytes, {PvtTextSource? source}) {
    var p = 0;

    // Extract null-terminated magic string

    const maxMagicLength = 32; // size limit on the null-terminated magic string
    while (bytes[p] != 0 && p < maxMagicLength && p < bytes.length) {
      p++;
    }
    if (p == 0 || p == bytes.length || bytes[p] != 0) {
      throw KeyBad('magic string not found');
    }

    final magicString = latin1.decode(bytes.sublist(0, p), allowInvalid: false);

    if (magicString != magicVersionId) {
      throw KeyUnsupported('unsupported type: $magicString');
    }
    p++; // skip over the null '\0'

    // Use a binary range to extract out length-value chunks from the rest
    //
    // From [The OpenSSH Private Key Format](https://coolaj86.com/articles/the-openssh-private-key-format/):
    //
    // "openssh-key-v1"0x00    # NULL-terminated "Auth Magic" string
    // 32-bit length, "none"   # ciphername length and string
    // 32-bit length, "none"   # kdfname length and string
    // 32-bit length, nil      # kdf (0 length, no kdf)
    // 32-bit 0x01             # number of keys, hard-coded to 1 (no length)
    // 32-bit length, sshpub   # public key in ssh format
    //    32-bit length, keytype
    //    32-bit length, pub0
    //    32-bit length, pub1
    // 32-bit length for rnd+prv+comment+pad
    //    64-bit dummy checksum?  # a random 32-bit int, repeated
    //    32-bit length, keytype  # the private key (including public)
    //    32-bit length, pub0     # Public Key parts
    //    32-bit length, pub1
    //    32-bit length, prv0     # Private Key parts
    //    ...                     # (number varies by type)
    //    32-bit length, comment  # comment string
    //    padding bytes 0x010203  # pad to block size (see notes below)
    //
    // Source code: https://github.com/openssh/openssh-portable/blob/master/sshkey.c

    final br = BinaryRange(bytes, begin: p);

    final cipherName = br.nextString();
    final kdfName = br.nextString();

    final kdfRange = br.nextBinary();
    final kdf = (kdfRange.isEmpty)
        ? Uint8List(0)
        : kdfRange.nextRawBytes(kdfRange.end - kdfRange.begin);
    assert(kdfRange.isEmpty);

    final numberOfKeys = br.nextUint32();
    if (numberOfKeys != 1) {
      throw KeyUnsupported('multiple keys not supported');
    }

    final publicKeyRange = br.nextBinary();

    final privateKeyRange = br.nextBinary();

    if (br.isNotEmpty) {
      throw KeyBad('unexpected extra data in OpenSSH private key');
    }

    // Save the bytes making up the public and private keys

    final publicKeyBytes = publicKeyRange.allRawBytes();
    final privateKeyBytes = privateKeyRange.allRawBytes();

    if (privateKeyBytes.length % 8 != 0) {
      throw KeyBad('private key part is not padded correctly');
    }

    return OpenSshPrivateKey(
        cipherName, kdfName, kdf, publicKeyBytes, privateKeyBytes, source);
  }

  //================================================================
  // Constants

  /// Expected magic value
  static const magicVersionId = 'openssh-key-v1';

  //================================================================
  // Members

  /// Name of encryption cipher
  String cipherName;

  /// Name of the key definition function
  String kdfName;

  /// Key definition function parameters
  Uint8List kdf; // can be zero bytes

  /// Bytes containing the public key
  Uint8List publicKeyBytes;

  /// Bytes containing the private key
  Uint8List privateKeyBytes;

  /// Text source from where the private key was decoded from
  ///
  /// Only non-null if the private key was decoded from text.

  final PvtTextSource? source;

  //================================================================
  // Methods

  /// The key-type (extracted from the bytes of the public key)
  String get publicKeyType => BinaryRange(publicKeyBytes).nextString();

  /// The key-type (extracted from the bytes of the private key)
  String get privateKeyType =>
      BinaryRange(privateKeyBytes, begin: 8).nextString();

  //================================================================

  @override
  Uint8List encode() {
    final bytes = <int>[];

    // The "openssh-key-v1" null terminated

    // ignore: cascade_invocations
    bytes
      ..addAll(latin1.encode(magicVersionId))
      ..add(0); // null terminate

    // Values with a length before them:

    // ignore: cascade_invocations
    bytes.addAll(BinaryLengthValue.encode([
      BinaryLengthValue.fromString(cipherName),
      BinaryLengthValue.fromString(kdfName),
      BinaryLengthValue(kdf)
    ]));

    // ignore: cascade_invocations
    bytes.addAll(Uint8List.fromList([0, 0, 0, 1])); // number of keys: no length

    // Keys: also values with a length before them

    // ignore: cascade_invocations
    bytes.addAll(BinaryLengthValue.encode([
      BinaryLengthValue(publicKeyBytes),
      BinaryLengthValue(privateKeyBytes)
    ]));

    final result = Uint8List.fromList(bytes);

    return result;
  }

/*
  String encode() {
    // Key-type is the same as the first chunk

    final keyType = chunks.keyType;

    // Only include the comment if its value is not empty.

    var spaceComment = '';

    if (comment != null) {
      var s = comment;
      s = s.replaceAll('\t', ' ');
      s = s.replaceAll('\n', ' ');
      s = s.replaceAll('\r', ' ');
      s = s.trim();

      if (s.isNotEmpty) {
        spaceComment = ' $s'; // add a space in front of the comment
      }
    }

    // Produce the one-line encoding

    return '$keyType ${base64.encode(chunks.encode())}$spaceComment';
  }


 */
  //================================================================
  // Static methods

}
