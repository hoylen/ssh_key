part of ssh_key_bin;

//################################################################
/// Abstract base class for all binary formats.
///
/// All binary formats have an [encode] method to encode the object into a
/// sequence of bytes.

//ignore: one_member_abstracts
abstract class BinaryFormat {
  /// Encode into bytes.
  Uint8List encode();
}
