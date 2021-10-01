/// Tests for Multiple Precision Integer (mpint) encoding and decoding.

//library ssh_key;

import 'dart:typed_data';

import 'package:test/test.dart';

import 'package:ssh_key/ssh_key_bin.dart';
import 'package:ssh_key/ssh_key.dart' show KeyBad;

//################################################################
// Classes to represent test data.

//================================================================
/// Base class

abstract class MPIntBase {
  MPIntBase(List<int> rep) : representation = Uint8List.fromList(rep);

  final Uint8List representation;

  String get name;
  BigInt get value;
}

//================================================================
/// Test data from hex string.

class MPIntHex extends MPIntBase {
  MPIntHex(this._hex, List<int> rep) : super(rep);

  final String _hex;

  @override
  String get name => 'hex:$_hex';

  @override
  BigInt get value {
    if (!_hex.startsWith('-')) {
      // Positive number
      return BigInt.from(int.parse(_hex, radix: 16));
    } else {
      // Negative number
      final str = '00${_hex.substring(1)}';
      final n = BigInt.from(int.parse(str, radix: 16));
      return -n;
    }
  }
}

//================================================================
/// Test data from int.

class MPIntDec extends MPIntBase {
  MPIntDec(this._value, List<int> rep) : super(rep);

  final int _value;

  @override
  String get name => 'dec:$_value';

  @override
  BigInt get value => BigInt.from(_value);
}

//################################################################

void testMPInt() {
  group('mpint', () {
    final examples = [
      // Zero

      MPIntDec(0, [0x00, 0x00, 0x00, 0x00]),

      // Positive values

      MPIntDec(1, [0x00, 0x00, 0x00, 0x01, 0x01]),
      MPIntDec(2, [0x00, 0x00, 0x00, 0x01, 0x02]),

      MPIntDec(127, [0x00, 0x00, 0x00, 0x01, 0x7F]), // 007F
      MPIntDec(128, [0x00, 0x00, 0x00, 0x02, 0x00, 0x80]), // 0080
      MPIntDec(129, [0x00, 0x00, 0x00, 0x02, 0x00, 0x81]), // 0081

      MPIntDec(255, [0x00, 0x00, 0x00, 0x02, 0x00, 0xFF]), // 00FF
      MPIntDec(256, [0x00, 0x00, 0x00, 0x02, 0x01, 0x00]), // 0100
      MPIntDec(257, [0x00, 0x00, 0x00, 0x02, 0x01, 0x01]), // 0101

      MPIntDec(32767, [0x00, 0x00, 0x00, 0x02, 0x7F, 0xFF]), // 007FFF
      MPIntDec(32768, [0x00, 0x00, 0x00, 0x03, 0x00, 0x80, 0x00]), // 008000
      MPIntDec(32769, [0x00, 0x00, 0x00, 0x03, 0x00, 0x80, 0x01]), // 008001

      MPIntDec(65535, [0x00, 0x00, 0x00, 0x03, 0x00, 0xFF, 0xFF]), // 00FFFF
      MPIntDec(65536, [0x00, 0x00, 0x00, 0x03, 0x01, 0x00, 0x00]), // 010000
      MPIntDec(65537, [0x00, 0x00, 0x00, 0x03, 0x01, 0x00, 0x01]), // 010000

      // Negative values

      MPIntDec(-1, [0x00, 0x00, 0x00, 0x01, 0xFF]),
      MPIntDec(-2, [0x00, 0x00, 0x00, 0x01, 0xFE]),

      MPIntDec(-127, [0x00, 0x00, 0x00, 0x01, 0x81]), // 81
      MPIntDec(-128, [0x00, 0x00, 0x00, 0x01, 0x80]), // 80
      MPIntDec(-129, [0x00, 0x00, 0x00, 0x02, 0xFF, 0x7F]), // FF7F

      MPIntDec(-255, [0x00, 0x00, 0x00, 0x02, 0xFF, 0x01]), // FF01
      MPIntDec(-256, [0x00, 0x00, 0x00, 0x02, 0xFF, 0x00]), // FF00
      MPIntDec(-257, [0x00, 0x00, 0x00, 0x02, 0xFE, 0xFF]), // FEFF

      MPIntDec(-32767, [0x00, 0x00, 0x00, 0x02, 0x80, 0x01]), // 8001
      MPIntDec(-32768, [0x00, 0x00, 0x00, 0x02, 0x80, 0x00]), // 8000
      MPIntDec(-32769, [0x00, 0x00, 0x00, 0x03, 0xFF, 0x7F, 0xFF]), // FF7FFF

      MPIntDec(-65535, [0x00, 0x00, 0x00, 0x03, 0xFF, 0x00, 0x01]), // FF0001
      MPIntDec(-65536, [0x00, 0x00, 0x00, 0x03, 0xFF, 0x00, 0x00]), // FF0000
      MPIntDec(-65537, [0x00, 0x00, 0x00, 0x03, 0xFE, 0xFF, 0xFF]), // FF0000

      // Examples from RFC 4251
      // https://tools.ietf.org/html/rfc4251#section-5

      MPIntHex('0', [0x00, 0x00, 0x00, 0x00]),
      MPIntHex('9a378f9b2e332a7', [
        0x00,
        0x00,
        0x00,
        0x08,
        0x09,
        0xa3,
        0x78,
        0xf9,
        0xb2,
        0xe3,
        0x32,
        0xa7
      ]),
      MPIntHex('80', [0x00, 0x00, 0x00, 0x02, 0x00, 0x80]),
      MPIntHex('-1234', [0x00, 0x00, 0x00, 0x02, 0xed, 0xcc]),
      MPIntHex(
          '-deadbeef', [0x00, 0x00, 0x00, 0x05, 0xff, 0x21, 0x52, 0x41, 0x11]),
    ];

    //----------------

    group('decode', () {
      for (final expected in examples) {
        test(expected.name, () {
          final bytes = BinaryRange(expected.representation);

          final parsedValue = bytes.nextMPInt();

          expect(parsedValue, equals(expected.value));
          expect(bytes, isEmpty, reason: 'unexpected bytes left over');
        });
      }
    });

    //----------------

    group('encode', () {
      for (final expected in examples) {
        test(expected.name, () {
          final encodedBytes = BinaryLengthValue.encode(
              [BinaryLengthValue.fromBigInt(expected.value)]);

          expect(encodedBytes, equals(expected.representation));
        });
      }
    });

    //----------------

    group('errors', () {
      <String, List<int>>{
        'incomplete data 1': [0x00, 0x00, 0x00, 0x01],
        'incomplete data 2': [0x00, 0x00, 0x00, 0x02, 0x11],
        'incomplete data 3': [0x00, 0x00, 0x00, 0x03, 0x11, 0x22],
      }.forEach((title, badBytes) {
        test(title, () {
          try {
            BinaryRange(Uint8List.fromList(badBytes)).nextMPInt();
            fail('did not throw exception');
          } on KeyBad catch (e) {
            expect(e.message, equals('data incomplete'));
          }
        });
      });

      <String, List<int>>{
        'bad zero 1': [0x00, 0x00, 0x00, 0x01, 0x00],
        'bad zero 2': [0x00, 0x00, 0x00, 0x02, 0x00, 0x00],
        'bad zero 3': [0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00],
        'unnecessary leading 0x00': [0x00, 0x00, 0x00, 0x02, 0x00, 0x33],
        'unnecessary leading 0xFF': [0x00, 0x00, 0x00, 0x02, 0xFF, 0x83],
      }.forEach((title, badBytes) {
        test(title, () {
          try {
            BinaryRange(Uint8List.fromList(badBytes)).nextMPInt();
            fail('did not throw exception');
          } on KeyBad catch (e) {
            expect(e.message, equals('invalid mpint'));
          }
        });
      });
    });
  });
}

void testString() {
  group('string', () {
    final examples = {
      '': [0x00, 0x00, 0x00, 0x00],
      'Hello': [0x00, 0x00, 0x00, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f]
    };

    group('decode', () {
      examples.forEach((str, enc) {
        test('decoding "$str"', () {
          final br = BinaryRange(Uint8List.fromList(enc));
          final extracted = br.nextString();
          expect(extracted, equals(str));
          expect(br.isEmpty, isTrue);
          expect(br.isNotEmpty, isFalse);
        });
      });
    });

    group('encode', () {
      examples.forEach((str, enc) {
        test('encoding "$str"', () {
          final encodedBytes =
              BinaryLengthValue.encode([BinaryLengthValue.fromString(str)]);
          expect(encodedBytes, equals(enc));
        });
      });
    });

    group('errors', () {
      test('string insufficient bytes', () {
        try {
          BinaryRange(Uint8List.fromList([0x00, 0x00, 0x00, 0x01]))
              .nextString();
          fail('did not throw exception');
        } on KeyBad catch (e) {
          expect(e.message, equals('data incomplete'));
        }
      });
    });
  });
}

void testBinary() {
  group('binary', () {
    group('errors', () {
      for (final incompleteData in [
        <int>[],
        [0x00],
        [0x00, 0x00],
        [0x00, 0x00, 0x00, 0x01],
        [0x00, 0x00, 0x00, 0x02],
        [0x00, 0x00, 0x00, 0x02, 0xFF],
        [0x00, 0x00, 0x00, 0x03],
        [0x00, 0x00, 0x00, 0x03, 0xFF],
        [0x00, 0x00, 0x00, 0x03, 0xFF, 0xFF],
      ]) {
        test('binary with ${incompleteData.length} bytes', () {
          try {
            BinaryRange(Uint8List.fromList(incompleteData)).nextBinary();
            fail('did not throw exception');
          } on KeyBad catch (e) {
            expect(e.message, equals('data incomplete'));
          }
        });
      }
    });
  });
}

void testUint32() {
  group('uint32', () {
    group('errors', () {
      for (final incompleteData in [
        <int>[],
        [0x00],
        [0x00, 0x00],
        [0x00, 0x00, 0x00],
      ]) {
        test('uint32 with ${incompleteData.length} bytes', () {
          try {
            BinaryRange(Uint8List.fromList(incompleteData)).nextUint32();
            fail('did not throw exception');
          } on KeyBad catch (e) {
            expect(e.message, equals('data incomplete'));
          }
        });
      }
    });
  });
}
//================================================================

void main() {
  testMPInt();
  testString();
  testBinary();
  testUint32();
}
