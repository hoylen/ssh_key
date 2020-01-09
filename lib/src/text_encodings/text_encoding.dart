part of ssh_key_txt;

//################################################################
/// Base class for all text encodings.

// ignore: one_member_abstracts
abstract class PubTextEncoding {
  /// Encode into text
  String encode();
}

//################################################################
/// Base class for all text encodings that can be encrypted

// ignore: one_member_abstracts
abstract class PvtTextEncoding {
  /// Encode into text and encrypt with passphrase
  String encode(String passphrase);
}

//################################################################
/// Indicates where the text encoding was decoded from.
///
/// The text is the substring of [str] from [begin] to [end].

class TextSource {
  //================================================================
  // Constructors

  //----------------------------------------------------------------
  /// Constructor when the format is not known yet.
  ///
  /// This is used by the RFC7468 text encoding, since the format is determined
  /// by examining the encapsulation label (i.e. after it has been decoded).
  /// When the label is examined and the data decoded. When the format is known,
  /// create a [PubTextSource] or [PvtTextSource] with the additional format
  /// information.

  TextSource._internal(this.str, this.begin, this.end);

  //================================================================
  // Members

  //----------------------------------------------------------------

  /// Source the data was decoded from.
  ///
  /// The actual subset of the source can be obtained by using the [decodedText]
  /// method.

  final String str;

  /// Offset into the source string where the data starts.

  final int begin;

  /// Offset into the source string where the data ends.

  final int end;

  //================================================================
  // Methods

  //----------------------------------------------------------------
  /// The text that was decoded to produce the data.

  String get decodedText => str.substring(begin, end);
}

//################################################################
/// Indicates where the text encoding was decoded from.
///
/// The text is the substring of [str] from [begin] to [end].
/// It was identified and decoded as [encoding].

class PubTextSource extends TextSource {
  //================================================================
  // Constructors

  //----------------------------------------------------------------
  /// Constructor

  PubTextSource(String str, int begin, int end, this.encoding)
      : super._internal(str, begin, end);

  //----------------------------------------------------------------
  /// Constructor from a TextSource

  PubTextSource.setEncoding(TextSource src, this.encoding)
      : super._internal(src.str, src.begin, src.end);

  //================================================================
  // Members

  /// The public key format that the decoded text was interpreted as.

  final PubKeyEncoding encoding;
}

//################################################################
/// Indicates where the text encoding was decoded from.
///
/// The text is the substring of [str] from [begin] to [end].
/// It was identified and decoded as [encoding].

class PvtTextSource extends TextSource {
  //================================================================
  // Constructors

  //----------------------------------------------------------------
  /// Constructor

  PvtTextSource(String str, int begin, int end, this.encoding)
      : super._internal(str, begin, end);

  //----------------------------------------------------------------
  /// Constructor from a TextSource.

  PvtTextSource.setEncoding(TextSource src, this.encoding)
      : super._internal(src.str, src.begin, src.end);

  //================================================================
  // Members

  /// The private key format that the decoded text was interpreted as.

  final PvtKeyEncoding encoding;
}
