part of ssh_key;

//################################################################
/// Supported public key encodings.
///
/// This enumeration is used to indicate the format that was decoded, or to
/// specify the desired format to the `encode` method in [PublicKeyExt].
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
/// This encoding starts with "---- BEGIN SSH2 PUBLIC KEY ----". For example,
///
/// ```
/// ---- BEGIN SSH2 PUBLIC KEY ----
/// Comment: "user@example.com"
/// AAAAB3NzaC1yc2EAAAADAQABAAABAQDYwd6O4Z+STMxTlFCPcN8VAq9ZNKvaQRYbsEDKK0
/// ydvTxdwt72xRo8supYX1vgDgRpYBhgDy8OPEMLDuk61sXRdbTITFW1B98rUsvvLEYHM4wJ
/// QnkWZvcyZz79id2H3r75ow+EL6SF4zxrSnJ9Ax09cKN2oM3nQUn0jkaqG4Hb/thbKbF8Sz
/// evBrcI0Ld4K64Mduc2XQbW2qMikT4xPBtu7bwPuP1XhipZOBcCBnXdrWCZk6pfYtA/aq5E
/// n7a2JAyglIpEsAIbtSVmj62BgstmSOy/4tQjVinh6IG8y8ixq59GbmC8KP9zUQ3hhLfT/n
/// qreXpeh039cotUTWJHyVOB
//---- END SSH2 PUBLIC KEY ----
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
/// This encoding starts with "-----BEGIN RSA PUBLIC KEY-----". For example,
///
/// ```
/// -----BEGIN RSA PUBLIC KEY-----
/// MIIBCgKCAQEA2MHejuGfkkzMU5RQj3DfFQKvWTSr2kEWG7BAyitMnb08XcLe9sUa
/// PLLqWF9b4A4EaWAYYA8vDjxDCw7pOtbF0XW0yExVtQffK1LL7yxGBzOMCUJ5Fmb3
/// Mmc+/Yndh96++aMPhC+kheM8a0pyfQMdPXCjdqDN50FJ9I5GqhuB2/7YWymxfEs3
/// rwa3CNC3eCuuDHbnNl0G1tqjIpE+MTwbbu28D7j9V4YqWTgXAgZ13a1gmZOqX2LQ
/// P2quRJ+2tiQMoJSKRLACG7UlZo+tgYLLZkjsv+LUI1Yp4eiBvMvIsaufRm5gvCj/
/// c1EN4YS30/56q3l6XodN/XKLVE1iR8lTgQIDAQAB
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
/// textual encoding of binary data conforming to the Subject Public Key Info
/// production.
///
/// This encoding starts with "-----BEGIN PUBLIC KEY-----". For example,
///
/// ```
/// -----BEGIN PUBLIC KEY-----
/// MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2MHejuGfkkzMU5RQj3Df
/// FQKvWTSr2kEWG7BAyitMnb08XcLe9sUaPLLqWF9b4A4EaWAYYA8vDjxDCw7pOtbF
/// 0XW0yExVtQffK1LL7yxGBzOMCUJ5Fmb3Mmc+/Yndh96++aMPhC+kheM8a0pyfQMd
/// PXCjdqDN50FJ9I5GqhuB2/7YWymxfEs3rwa3CNC3eCuuDHbnNl0G1tqjIpE+MTwb
/// bu28D7j9V4YqWTgXAgZ13a1gmZOqX2LQP2quRJ+2tiQMoJSKRLACG7UlZo+tgYLL
/// Zkjsv+LUI1Yp4eiBvMvIsaufRm5gvCj/c1EN4YS30/56q3l6XodN/XKLVE1iR8lT
/// gQIDAQAB
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
/// This enumeration is used to indicate the format that was decoded, or to
// specify the desired format to the `encode` method in [PrivateKeySsh].
///
/// ## openSsh
///
/// OpenSSH private key format.
///
/// This is a proprietary encoding used by newer versions of the OpenSSH
/// implementation.
///
/// This encoding starts with "---- BEGIN OPENSSH PRIVATE KEY ----".
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
/// This encoding starts with "-----BEGIN PRIVATE KEY-----".

enum PvtKeyEncoding {
  /// OpenSSH Private Key
  openSsh,

  /// PuTTY Private Key
  puttyPrivateKey
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
