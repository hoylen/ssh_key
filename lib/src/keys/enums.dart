part of ssh_key;

//################################################################
/// Supported public key encodings.
///
/// This enumeration is used to indicate the format that a public key was
/// decoded from, or to specify the desired format to [PublicKeyExt.encode]
/// which is an extension to [pointy_castle.PublicKey].
///
/// ## openSsh
///
/// OpenSSH public key format.
///
/// This is a proprietary encoding used by the OpenSSH implementation of SSH.
///
/// This encoding is a single-line of text, consisting of: a key-type,
/// base-64 encoded data and an optional comment (all
/// separated by a space). For example,
///
/// ```
/// ssh-rsa AAAAB3NzaC1yc2EAAA...nqreXpeh039cotUTWJHyVOB user@example.com
/// ```
///
/// ## sshPublicKey
///
/// SSH public key file format as defined by RFC 4716.
///
/// This encoding is sometimes referred to as the "SSH2 public key" format
/// or the "new OpenSSH public key format".
///
/// This encoding starts with `---- BEGIN SSH2 PUBLIC KEY ----` (note: four
/// hyphens, instead of five used in the other formats).
///
/// For example,
///
/// ```
/// ---- BEGIN SSH2 PUBLIC KEY ----
/// Comment: "user@example.com"
/// AAAAB3NzaC1yc2EAAAADAQABAAABAQDYwd6O4Z+STMxTlFCPcN8VAq9ZNKvaQRYbsEDKK0
/// ydvTxdwt72xRo8supYX1vgDgRpYBhgDy8OPEMLDuk61sXRdbTITFW1B98rUsvvLEYHM4wJ
/// ...
/// ---- END SSH2 PUBLIC KEY ----
/// ```
///
/// ## pkcs1
///
/// Textual encoding of PKCS #1.
///
/// This encoding is often referred to as "PEM". But that term is ambiguous,
/// since PEM encoding is used to encode other types of binary data besides
/// public keys. Implementations of PEM encoding also vary.
///
/// This implementation uses the _textual encoding_ of RFC 7468, which
/// specifies a unified and interoperable version of PEM and PEM-like
/// text_encodings.
///
/// Strictly speaking, this encoding is not PKCS #1, but the RFC 7468
/// textual encoding of binary data conforming to PKCS #1.
///
/// This encoding starts with `-----BEGIN RSA PUBLIC KEY-----`. For example,
///
/// ```
/// -----BEGIN RSA PUBLIC KEY-----
/// MIIBCgKCAQEA2MHejuGfkkzMU5RQj3DfFQKvWTSr2kEWG7BAyitMnb08XcLe9sUa
/// PLLqWF9b4A4EaWAYYA8vDjxDCw7pOtbF0XW0yExVtQffK1LL7yxGBzOMCUJ5Fmb3
/// ...
/// -----END RSA PUBLIC KEY-----
/// ```
///
/// Note: this format only supports RSA keys.
///
/// ## x509spki
///
/// Textual encoding of the _Subject Public Key Info_ production from X.509.
///
/// This is a proprietary encoding used by the OpenSSH implementation of SSH.
/// OpenSSH incorrectly and confusingly refers to this encoding as "PKCS #8".
/// But this encoding is not related to real PKCS #8, which is an encoding of
/// private keys and not public keys.
///
/// This encoding is not defined by X.509. That specification only defines an
/// ASN.1 production which is unofficially borrowed by this encoding.
/// Strictly speaking, this encoding is the RFC 7468
/// textual encoding of binary data conforming to the _Subject Public Key Info_
/// production.
///
/// This encoding starts with `-----BEGIN PUBLIC KEY-----`. For example,
///
/// ```
/// -----BEGIN PUBLIC KEY-----
/// MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2MHejuGfkkzMU5RQj3Df
/// FQKvWTSr2kEWG7BAyitMnb08XcLe9sUaPLLqWF9b4A4EaWAYYA8vDjxDCw7pOtbF
/// ...
/// -----END PUBLIC KEY-----
/// ```

enum PubKeyEncoding {
  /// OpenSSH Public Key
  openSsh,

  /// SSH Public Key
  sshPublicKey,

  /// Textual encoding of PKCS #1
  pkcs1,

  /// Textual encoding of subjectPublicKeyInfo from X.509
  x509spki
}

//################################################################
/// Supported private key encodings.
///
/// This enumeration is used to indicate the format that a private key was
/// decoded from, or to specify the desired format to [PrivateKeyExt.encode]
/// which is an extension on [pointy_castle.PrivateKey].
///
/// ## openSsh
///
/// OpenSSH private key format.
///
/// This is a proprietary encoding used by newer versions of the OpenSSH
/// implementation.
///
/// This encoding starts with `-----BEGIN OPENSSH PRIVATE KEY-----`.
/// For example:
///
/// ```
/// -----BEGIN OPENSSH PRIVATE KEY-----
/// b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdz
/// c2gtcnNhAAAAAwEAAQAAAQEA2MHejuGfkkzMU5RQj3DfFQKvWTSr2kEWG7BAyitM
/// ...
/// -----END OPENSSH PRIVATE KEY-----
/// ```
///
/// ## puttyPrivateKey
///
/// Private key format used by PuTTY, an SSH client for Microsoft Windows.
///
/// This encoding starts with a line beginning with `PuTTY-User-Key-File-2:`
/// For example,
///
/// ```
/// PuTTY-User-Key-File-2: ssh-rsa
/// Encryption: none
/// Comment:
/// Public-Lines: 6
/// AAAAB3NzaC1yc2EAAAADAQABAAABAQDYwd6O4Z+STMxTlFCPcN8VAq9ZNKvaQRYb
/// sEDKK0ydvTxdwt72xRo8supYX1vgDgRpYBhgDy8OPEMLDuk61sXRdbTITFW1B98r
/// ...
/// Private-Lines: 14
/// AAABAQCfdbhaGsf+o/rpPcIqVFn5JfmDwcjvjlRKWFbBpCsAHFgNji/jEMulfeYC
/// z1xSr101fFlSSblPWqvjtbuE6r2qw1IUzHt862aVg5q9wC9gWt6ZbUqRXXxbmzLu
/// ...
/// Private-MAC: 73aa9bbe1b00c5f2c2fdb777dd8d749213f313f3
/// ```
///
/// ## pkcs1
///
/// Textual encoding of PKCS #1.
///
/// This encoding is often referred to as "PEM". But that term is ambiguous,
/// since PEM encoding is used to encode other types of binary data besides
/// public keys. Implementations of PEM encoding also vary.
///
/// This encoding is used by older versions of OpenSSH.
///
/// This implementation uses the _textual encoding_ of RFC 7468, which
/// specifies a unified and interoperable version of PEM and PEM-like
/// text_encodings.
///
/// Strictly speaking, this encoding is not PKCS #1, but the RFC 7468
/// textual encoding of binary data conforming to PKCS #1.
///
/// This encoding starts with `-----BEGIN RSA PRIVATE KEY-----`. For example,
///
/// ```
/// -----BEGIN RSA PRIVATE KEY-----
/// AAAAAAAAAQEA2MHejuGfkkzMU5RQj3DfFQKvWTSr2kEWG7BAyitMnb08XcLe9sUa
/// PLLqWF9b4A4EaWAYYA8vDjxDCw7pOtbF0XW0yExVtQffK1LL7yxGBzOMCUJ5Fmb3
/// ...
/// -----END RSA PRIVATE KEY-----
/// ```

enum PvtKeyEncoding {
  /// OpenSSH Private Key
  openSsh,

  /// PuTTY Private Key
  puttyPrivateKey,

  /// RSA Private Key
  ///
  /// This is also the original OpenSSH private key format (before it switched
  /// to using the new [openSsh] format).
  pkcs1,
}

//################################################################
/// Types of fingerprints of public keys.
///
/// Used by [RSAPublicKeyWithInfo.fingerprint] to specify what type of algorithm to
/// use to generate the fingerprint.
///
/// Example of a SHA-256 fingerprint:
///
/// `SHA256:yKe8u3tiTOwRhJk9yU0npcQf7t8zxlP2KY7UwspYLBs`
///
/// Example of a MD5 fingerprint:
///
/// `MD5:12:be:93:1f:16:34:b1:0d:4a:19:d9:b5:5b:da:d5:76`

enum FingerprintType {
  /// Fingerprint using the SHA-256 algorithm

  sha256,

  /// Fingerprint using the MD5 algorithm

  md5
}
