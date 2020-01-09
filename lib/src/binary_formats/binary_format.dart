part of ssh_key_bin;

//################################################################
/// Base class for all binary formats.

//ignore: one_member_abstracts
abstract class BinaryFormat {
  /// Encode into bytes.
  Uint8List encode();
}
