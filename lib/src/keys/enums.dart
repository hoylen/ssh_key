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
/// This encoding starts with "---- BEGIN SSH2 PUBLIC KEY ----" (note: four
/// hyphens, not the usual five).
///
/// For example,
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
/// textual encoding of binary data conforming to the _Subject Public Key Info_
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
/// This encoding starts with "-----BEGIN OPENSSH PRIVATE KEY-----".
/// For example:
///
/// ```
/// -----BEGIN OPENSSH PRIVATE KEY-----
/// b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdz
/// c2gtcnNhAAAAAwEAAQAAAQEA2MHejuGfkkzMU5RQj3DfFQKvWTSr2kEWG7BAyitM
/// nb08XcLe9sUaPLLqWF9b4A4EaWAYYA8vDjxDCw7pOtbF0XW0yExVtQffK1LL7yxG
/// BzOMCUJ5Fmb3Mmc+/Yndh96++aMPhC+kheM8a0pyfQMdPXCjdqDN50FJ9I5GqhuB
/// 2/7YWymxfEs3rwa3CNC3eCuuDHbnNl0G1tqjIpE+MTwbbu28D7j9V4YqWTgXAgZ1
/// 3a1gmZOqX2LQP2quRJ+2tiQMoJSKRLACG7UlZo+tgYLLZkjsv+LUI1Yp4eiBvMvI
/// saufRm5gvCj/c1EN4YS30/56q3l6XodN/XKLVE1iR8lTgQAAA7gAAAAAAAAAAAAA
/// AAdzc2gtcnNhAAABAQDYwd6O4Z+STMxTlFCPcN8VAq9ZNKvaQRYbsEDKK0ydvTxd
/// wt72xRo8supYX1vgDgRpYBhgDy8OPEMLDuk61sXRdbTITFW1B98rUsvvLEYHM4wJ
/// QnkWZvcyZz79id2H3r75ow+EL6SF4zxrSnJ9Ax09cKN2oM3nQUn0jkaqG4Hb/thb
/// KbF8SzevBrcI0Ld4K64Mduc2XQbW2qMikT4xPBtu7bwPuP1XhipZOBcCBnXdrWCZ
/// k6pfYtA/aq5En7a2JAyglIpEsAIbtSVmj62BgstmSOy/4tQjVinh6IG8y8ixq59G
/// bmC8KP9zUQ3hhLfT/nqreXpeh039cotUTWJHyVOBAAAAAwEAAQAAAQEAn3W4WhrH
/// /qP66T3CKlRZ+SX5g8HI745USlhWwaQrABxYDY4v4xDLpX3mAs9cUq9dNXxZUkm5
/// T1qr47W7hOq9qsNSFMx7fOtmlYOavcAvYFremW1KkV18W5sy7uh+jdcjXZlE7/Tw
/// rwKlzzR8l1U0LJ/x0XKpJ4iTdJM6jygfV4x/2HOuHxEXovoSUutxAejhbHqWiApr
/// hEI7JemFfRC0/HAyKsXbnv9tmnUH4aOtDsx2RwvCzv1LtGC8tobkm3RSRmrsT/o0
/// zjeS5QCO1AVqImIuYhdv8Ddbf/BvSANg3kQ+sGvnDO/o+PXtNqXkl15Vbi/bvQRK
/// A+sdzAviCJCOwQAAAIBnGMa/WL/8d0whd5SZVe7PSa6owdKFTFrB4Y/O7IZMin32
/// nDLJyqBeTWUev6AlWCo1XQ7HZgPUflE/Px2SeoBq+nZE3JmilHU/KTwoMysgNfB4
/// KO40VUtEgCfEHmLGtOsG3HTZHnEIcmIJwQsvJfRplmVJJVQ8dU9eq8B1TwuABQAA
/// AIEA+MFThA474/CVBFjao6/7l+LqRWwUVPfmNg7pQbRf8MlGNc3ekXgd3wtjUlVx
/// Nf1JVtcauR38f5ZVDL8Bu2H7emxn1GQFqku4lwVKOIXM2H0WPk2zBcqNMRfZS6Tr
/// QsLZPkzVJvxHVjMAaS2UpA5yY9PsuOYamAWcCGYA8PWk7ukAAACBAN8R+QRjAPiY
/// lOqGYxDm+Bv0DwNsQ5xDCOHph7znyYNZ8lttxStprye5TuLJoTrfSJjJSN+yh3Me
/// CQD6x4DiMftA8uubkmhgbnoKXSfGrkaCUG2R3wB0+9HYih2LN7tCxMfdPGRw4gcq
/// dIlYCSS1XQpYZ+PxLegbcHLTUOhiglDZAQIDBAUG
/// -----END OPENSSH PRIVATE KEY-----
/// ```
///
/// ## puttyPrivateKey
///
/// Private key format used by Putty.
///
/// This encoding starts with a line beginning with "PuTTY-User-Key-File-2:"
/// For example,
///
/// ```
/// PuTTY-User-Key-File-2: ssh-rsa
/// Encryption: none
/// Comment:
/// Public-Lines: 6
/// AAAAB3NzaC1yc2EAAAADAQABAAABAQDYwd6O4Z+STMxTlFCPcN8VAq9ZNKvaQRYb
/// sEDKK0ydvTxdwt72xRo8supYX1vgDgRpYBhgDy8OPEMLDuk61sXRdbTITFW1B98r
/// UsvvLEYHM4wJQnkWZvcyZz79id2H3r75ow+EL6SF4zxrSnJ9Ax09cKN2oM3nQUn0
/// jkaqG4Hb/thbKbF8SzevBrcI0Ld4K64Mduc2XQbW2qMikT4xPBtu7bwPuP1XhipZ
/// OBcCBnXdrWCZk6pfYtA/aq5En7a2JAyglIpEsAIbtSVmj62BgstmSOy/4tQjVinh
/// 6IG8y8ixq59GbmC8KP9zUQ3hhLfT/nqreXpeh039cotUTWJHyVOB
/// Private-Lines: 14
/// AAABAQCfdbhaGsf+o/rpPcIqVFn5JfmDwcjvjlRKWFbBpCsAHFgNji/jEMulfeYC
/// z1xSr101fFlSSblPWqvjtbuE6r2qw1IUzHt862aVg5q9wC9gWt6ZbUqRXXxbmzLu
/// 6H6N1yNdmUTv9PCvAqXPNHyXVTQsn/HRcqkniJN0kzqPKB9XjH/Yc64fERei+hJS
/// 63EB6OFsepaICmuEQjsl6YV9ELT8cDIqxdue/22adQfho60OzHZHC8LO/Uu0YLy2
/// huSbdFJGauxP+jTON5LlAI7UBWoiYi5iF2/wN1t/8G9IA2DeRD6wa+cM7+j49e02
/// peSXXlVuL9u9BEoD6x3MC+IIkI7BAAAAgQD4wVOEDjvj8JUEWNqjr/uX4upFbBRU
/// 9+Y2DulBtF/wyUY1zd6ReB3fC2NSVXE1/UlW1xq5Hfx/llUMvwG7Yft6bGfUZAWq
/// S7iXBUo4hczYfRY+TbMFyo0xF9lLpOtCwtk+TNUm/EdWMwBpLZSkDnJj0+y45hqY
/// BZwIZgDw9aTu6QAAAIEA3xH5BGMA+JiU6oZjEOb4G/QPA2xDnEMI4emHvOfJg1ny
/// W23FK2mvJ7lO4smhOt9ImMlI37KHcx4JAPrHgOIx+0Dy65uSaGBuegpdJ8auRoJQ
/// bZHfAHT70diKHYs3u0LEx908ZHDiByp0iVgJJLVdClhn4/Et6BtwctNQ6GKCUNkA
/// AACAZxjGv1i//HdMIXeUmVXuz0muqMHShUxaweGPzuyGTIp99pwyycqgXk1lHr+g
/// JVgqNV0Ox2YD1H5RPz8dknqAavp2RNyZopR1Pyk8KDMrIDXweCjuNFVLRIAnxB5i
/// xrTrBtx02R5xCHJiCcELLyX0aZZlSSVUPHVPXqvAdU8LgAU=
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
/// This encoding starts with "-----BEGIN RSA PRIVATE KEY-----". For example,
///
/// ```
/// -----BEGIN RSA PRIVATE KEY-----
/// AAAAAAAAAQEA2MHejuGfkkzMU5RQj3DfFQKvWTSr2kEWG7BAyitMnb08XcLe9sUa
/// PLLqWF9b4A4EaWAYYA8vDjxDCw7pOtbF0XW0yExVtQffK1LL7yxGBzOMCUJ5Fmb3
/// Mmc+/Yndh96++aMPhC+kheM8a0pyfQMdPXCjdqDN50FJ9I5GqhuB2/7YWymxfEs3
/// rwa3CNC3eCuuDHbnNl0G1tqjIpE+MTwbbu28D7j9V4YqWTgXAgZ13a1gmZOqX2LQ
/// P2quRJ+2tiQMoJSKRLACG7UlZo+tgYLLZkjsv+LUI1Yp4eiBvMvIsaufRm5gvCj/
/// c1EN4YS30/56q3l6XodN/XKLVE1iR8lTgQAAAAMBAAEAAAEBAJ91uFoax/6j+uk9
/// wipUWfkl+YPByO+OVEpYVsGkKwAcWA2OL+MQy6V95gLPXFKvXTV8WVJJuU9aq+O1
/// u4TqvarDUhTMe3zrZpWDmr3AL2Ba3pltSpFdfFubMu7ofo3XI12ZRO/08K8Cpc80
/// fJdVNCyf8dFyqSeIk3STOo8oH1eMf9hzrh8RF6L6ElLrcQHo4Wx6logKa4RCOyXp
/// hX0QtPxwMirF257/bZp1B+GjrQ7MdkcLws79S7RgvLaG5Jt0UkZq7E/6NM43kuUA
/// jtQFaiJiLmIXb/A3W3/wb0gDYN5EPrBr5wzv6Pj17Tal5JdeVW4v270ESgPrHcwL
/// 4giQjsEAAACBAPjBU4QOO+PwlQRY2qOv+5fi6kVsFFT35jYO6UG0X/DJRjXN3pF4
/// Hd8LY1JVcTX9SVbXGrkd/H+WVQy/Abth+3psZ9RkBapLuJcFSjiFzNh9Fj5NswXK
/// jTEX2Uuk60LC2T5M1Sb8R1YzAGktlKQOcmPT7LjmGpgFnAhmAPD1pO7pAAAAgQDf
/// EfkEYwD4mJTqhmMQ5vgb9A8DbEOcQwjh6Ye858mDWfJbbcUraa8nuU7iyaE630iY
/// yUjfsodzHgkA+seA4jH7QPLrm5JoYG56Cl0nxq5GglBtkd8AdPvR2Iodize7QsTH
/// 3TxkcOIHKnSJWAkktV0KWGfj8S3oG3By01DoYoJQ2QAAAIEAsTnrqpYJjWiGgsZb
/// X2uuMJR2nGdYRQEpfzI4dZtxDzgXUZYPEE0n2xVd+fbt5a1DZx9x5pm6n5wXlDEx
/// prM0XBCIGQX6E05HgTE/o+2P+F2GT3VEKsgYt/Vp1z70bmgsJvrOkiwDFyLXFBhp
/// Ykj4rq76ZPFr2QuGE2W5HfOlQqEAAACBAI1qLG6OgRAYUte26FjPw9ycxWPLH7WR
/// fbESRj4Ix2RhAlbZ6RRThHnvbUYywua6pKBPgsZlvJ7LHLQlR5K6UytQim+5CYDo
/// GUF/Dn1n5BXJCUndHv2ALCBlYXHHT0aE1pFJ/L5EHdajIIvtZqaB34DueLY1sH+j
/// 3Y69zl30DV9JAAAAgGcYxr9Yv/x3TCF3lJlV7s9JrqjB0oVMWsHhj87shkyKffac
/// MsnKoF5NZR6/oCVYKjVdDsdmA9R+UT8/HZJ6gGr6dkTcmaKUdT8pPCgzKyA18Hgo
/// 7jRVS0SAJ8QeYsa06wbcdNkecQhyYgnBCy8l9GmWZUklVDx1T16rwHVPC4AF
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
