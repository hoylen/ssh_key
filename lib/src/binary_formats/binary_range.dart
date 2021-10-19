part of ssh_key_bin;

//################################################################
/// Helper class for decoding binary data.
///
/// A binary range represents a sequence of bytes to be decoded. As bytes
/// are processed, they are removed from the beginning of the sequence.
///
/// The binary range maintains a reference to the bytes. It does not make a copy
/// of them. Therefore, the program should not modify the bytes until after the
/// binary range is no longer needed.
///
/// Methods are available to remove bytes from the beginning of the binary
/// range.
///
/// For length-value pairs, which are represented by a 32-bit unsigned length
/// (i.e. four bytes) followed by that number of bytes for the value:
/// - [nextBinary] - sequence of bytes
/// - [nextMPInt] - multiple precision integer (BigInt)
/// - [nextString] - sequence of bytes interpreted as a UTF-8 encoded string
/// - [nextUint32] - big-ending 32-bit unsigned integer
///
/// For removing a sequence of bytes (without using the next four bytes as the
/// length), use [nextRawBytes] or [allRawBytes].
///
/// The amount of bytes remaining can be determined using
/// [isEmpty], [isNotEmpty] and [length].

class BinaryRange {
  //================================================================
  // Constructors

  //----------------------------------------------------------------
  /// Creates a new binary range from the [bytes], starting at the [begin]
  /// offset and ending at the [end] offset.
  ///
  /// If the _begin_ offset is not specified, it is initialized to the start of
  /// the _bytes_ (i.e. to offset zero).
  ///
  /// If the _end_ offset is not specified, it is initialized to after the last
  /// byte in the _data_ (i.e. to the length of the data).
  ///
  /// The _bytes_ are not copied, so the program should not change the data
  /// while the binary range is in use.

  BinaryRange(Uint8List bytes, {int? begin, int? end})
      : _bytes = bytes,
        _begin = begin ?? 0,
        _end = end ?? bytes.length;

  //----------------------------------------------------------------
  /// Creates a new binary range with the same values as another binary range.
  ///
  /// The two ranges can then be used to process the bytes independently of
  /// each other. That is, they maintain separate _begin_ offsets.
  ///
  /// This does not make a copy of the bytes that are referenced. Both ranges
  /// still share the same underlying bytes, so the bytes should not be modified
  /// until both ranges are no longer needed.

  BinaryRange.copy(BinaryRange original)
      : _bytes = original._bytes,
        _begin = original._begin,
        _end = original._end;

  //================================================================
  // Members

  //----------------------------------------------------------------
  /// The underlying data in the binary range.

  final Uint8List _bytes;

  /// The offset into the _bytes_ for the start of the binary range.
  ///
  /// This value will always be greater than or equal to zero, and less than or
  /// equal to the [_end].

  int _begin;

  /// The offset into the _bytes_ for the end of the binary range.
  ///
  /// This value will always be greater than or equal to zero, and less than or
  /// equal to the total length of the underlying _bytes_.

  final int _end;

  //================================================================
  // Methods

  /// Tests if there are one or more bytes in the range.

  bool get isNotEmpty => (_begin < _end);

  /// Tests if there are zero bytes in the range.

  bool get isEmpty => (_end <= _begin);

  /// Number of bytes in the range.

  int get length => (_end - _begin);

  /// Returns a copy of all the bytes in the range.
  ///
  /// The returned bytes can be modified without affecting the bytes in the
  /// binary range.
  ///
  /// Unlike the extract methods, the binary range is not changed by this
  /// operation.

  Uint8List allRawBytes() => _bytes.sublist(_begin, _end);

  //================================================================
  // Decoding methods

  //----------------------------------------------------------------
  /// Extract a sequence of bytes from the range.
  ///
  /// The [length] number of bytes are copied from the beginning of the range
  /// and returned. Those bytes are then no longer a part of the range.
  ///
  /// Throws a BadEncoding if there are less than _length_ bytes in the
  /// range, or the length is negative.

  Uint8List nextRawBytes(int length) {
    if (length < 0) {
      throw KeyBad('length is negative');
    }
    if (_end < _begin + length) {
      throw KeyBad('data incomplete (for $length bytes)');
    }

    final result = _bytes.sublist(_begin, _begin + length);

    _begin += length;

    return result;
  }

  //----------------------------------------------------------------
  /// Extracts a big-endian 32-bit unsigned integer from the range.
  ///
  /// Returns the value represented by the first four bytes of the range and
  /// removes those four bytes from the range.
  ///
  /// Throws a BadEncoding if there are insufficient bytes in the range.

  int nextUint32() {
    if (_end < _begin + 4) {
      // Less than 4 bytes left: not enough for a 32-bit value
      throw KeyBad('data incomplete (for 32-bit unsigned integer)');
    }

    final a = Uint8List.fromList([
      _bytes[_begin + 3],
      _bytes[_begin + 2],
      _bytes[_begin + 1],
      _bytes[_begin]
    ]);
    final value = a.buffer.asUint32List().first;

    _begin += 4;

    return value;
  }

  //----------------------------------------------------------------
  /// Extracts an arbitrary length binary string from the range.
  ///
  /// Extracts an uint32 which indicates the number of following bytes that make
  /// up the string value. The string does not have to be, and probably isn't,
  /// null terminated.
  ///
  /// Returns a new binary range consisting of the string's bytes. The result
  /// shares the same underlying bytes. The bytes making up the length and
  /// the string are removed from the range.
  ///
  /// This method is similar to [nextString], except the contents are not
  /// interpreted as UTF-8.
  ///
  /// Throws a BadEncoding if there are insufficient bytes in the range.

  BinaryRange nextBinary() {
    final length = nextUint32();

    if (_end < _begin + length) {
      throw KeyBad('data incomplete (for $length byte binary data)');
    }

    final result = BinaryRange(_bytes, begin: _begin, end: _begin + length);

    _begin += length;

    return result;
  }

  //----------------------------------------------------------------
  /// Extracts an arbitrary length UTF-8 string from the range.
  ///
  /// Extracts an uint32 which indicates the number of following bytes that make
  /// up the string value. The string does not have to be, and probably
  /// isn't, null terminated.
  ///
  /// Returns the string value obtained from interpreting the bytes using the
  /// [encoding]. The bytes making up the length and the string are removed
  /// from the range.
  ///
  /// This method is similar to [nextBinary], except the contents are
  /// interpreted as UTF-8 and returned as a String, instead of a range of
  /// binary bytes.
  ///
  /// Throws a KeyBad if there are insufficient bytes in the range.
  /// Throws an exception if the bytes are not correct for the encoding.

  String nextString({Encoding encoding = utf8}) {
    final length = nextUint32();

    if (_end < _begin + length) {
      throw KeyBad('data incomplete (for $length byte string)');
    }

    final rawString = _bytes.sublist(_begin, _begin + length);
    _begin += length;

    return encoding.decode(rawString);
  }

  //----------------------------------------------------------------
  /// Extracts a multiple precision integer from the range.
  ///
  /// Extracts an uint32 which indicates the number of following bytes to be
  /// interpreted as a two's complement integer. See section 5 of
  /// [RFC 4251](https://tools.ietf.org/html/rfc4251#section-5) for a definition
  /// of this format.
  ///
  /// Returns the integer value. The bytes making up the length and integer are
  /// removed from the range.
  ///
  /// Throws a BadEncoding if there are insufficient bytes in the range or
  /// the bytes do not represent a valid multiple precision integer.

  BigInt nextMPInt() {
    final length = nextUint32();

    // mpint
    //      Represents multiple precision integers in two's complement format,
    //      stored as a string, 8 bits per byte, MSB first.  Negative numbers
    //      have the value 1 as the most significant bit of the first byte of
    //      the data partition.  If the most significant bit would be set for
    //      a positive number, the number MUST be preceded by a zero byte.
    //      Unnecessary leading bytes with the value 0 or 255 MUST NOT be
    //      included.  The value zero MUST be stored as a string with zero
    //      bytes of data.

    if (length == 0) {
      // Zero is always represented by no bytes.
      return BigInt.zero;
    } else if (_begin + length <= _end) {
      // Length is correct

      // Process first byte

      final firstByte = _bytes[_begin];
      final negative = (firstByte & 0x80) != 0; // 1 MSB from first byte
      var n = BigInt.from(firstByte & 0x7F); // other 7 LSB from first byte
      _begin++; // skip first byte

      if (_begin == _end) {
        if (n == BigInt.zero && !negative) {
          // Zero must be represented by no bytes
          throw KeyBad('invalid mpint');
        }
      } else {
        final secondByte = _bytes[_begin];
        if (firstByte == 0x00 && (secondByte & 0x80 == 0x00) ||
            firstByte == 0xFF && (secondByte & 0x80 == 0x80)) {
          // Unnecessary leading bytes with 0 or 255 MUST NOT be included.
          throw KeyBad('invalid mpint');
        }
      }
      // Process remaining bytes

      for (var i = 1; i < length; i++) {
        n = (n << 8) | BigInt.from(_bytes[_begin++]);
      }

      // Return value (two's complement for negative numbers)

      return (negative) ? n - BigInt.two.pow((8 * length) - 1) : n;
    } else {
      throw KeyBad('data incomplete (for $length byte MPint)');
    }
  }
}
