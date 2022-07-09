import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';

import 'package:ssh_key/ssh_key.dart';
import 'package:ssh_key/ssh_key_txt.dart';

//----------------------------------------------------------------
/// Create data for the OpenSSH Public Key format.
///
/// This is a sequence of bytes that starts with the [keyType] followed by
/// the [bytes]. The _keyType_ is encoded as a 32-bit length followed by the
/// bytes of the _keyType_.
///
/// If [bytes] is null, test data is used.

Uint8List dataForOpenSshFormat(String keyType, [Uint8List? bytes]) {
  final algChunk = [0, 0, 0, keyType.length] + latin1.encode(keyType);

  final testChunk = [0, 0, 0, 1, 42];

  return Uint8List.fromList(algChunk + (bytes ?? testChunk));
}

//----------------------------------------------------------------

void valid() {
  group('valid data', () {
    final testKeyType = 'a';

    final testCases = {
      'a AAAAAWEAAAABKg==': dataForOpenSshFormat('a'),
      'ab AAAAAmFiAAAAASo=': dataForOpenSshFormat('ab'),
      'abc AAAAA2FiYwAAAAEq': dataForOpenSshFormat('abc'),
    };

    for (final testCase in testCases.entries) {
      final expectedEncoding = testCase.key;
      final data = testCase.value;

      group(expectedEncoding, () {
        test('encode', () {
          final x = GenericPublicKey(data);
          final enc = x.encode(PubKeyEncoding.openSsh);
          expect(enc, endsWith('\n'));
          expect(enc, equals('$expectedEncoding\n')); // encoding has "\n"
        });

        test('decoding line ending with LF', () {
          final endOfLineWithLF =
              OpenSshPublicKey.decode('$expectedEncoding\n');
          expect(endOfLineWithLF.comment, isNull);
        });

        test('decoding line ending with CR', () {
          final endOfLineWithCR =
              OpenSshPublicKey.decode('$expectedEncoding\r');
          expect(endOfLineWithCR.comment, isNull);
        });

        test('decoding line ending with CR-LF', () {
          final endOfLineWithCR =
              OpenSshPublicKey.decode('$expectedEncoding\r\n');
          expect(endOfLineWithCR.comment, isNull);
        });

        test('decoding line ending with comment', () {
          const expectedComment = '  foobar  '; // note spaces are significant
          final withComment =
              OpenSshPublicKey.decode('$expectedEncoding $expectedComment\n');
          expect(withComment.comment, equals(expectedComment));
        });
      });
    }
  });
}

//----------------------------------------------------------------

void invalid() {
  group('invalid data', () {
    final testCases = {
      'no data': Uint8List(0),
      'zero bytes data': Uint8List.fromList([0]),
      'key-type length is incomplete': Uint8List.fromList([0, 0, 0]),
      'key-type length is zero': Uint8List.fromList([0, 0, 0, 0]),
      'key-type length more than available bytes':
          Uint8List.fromList([0, 0, 0, 1]),
      'invalid length in keyType': Uint8List.fromList([0, 0, 0]),
      'no body in data': dataForOpenSshFormat('ssh-rsa', Uint8List(0)),
    };

    for (final testCase in testCases.entries) {
      final name = testCase.key;
      final data = testCase.value;

      test(name, () {
        try {
          final x = GenericPublicKey(data);
          x.encode(PubKeyEncoding.openSsh);
          fail('succeeded when it should have failed');
        } on KeyBad catch (e) {
          // expected exception
        }
      });
    }
  });
}

//----------------------------------------------------------------

void decode() {
  group('decode', () {
    test('empty string error', () {
      try {
        OpenSshPublicKey.decode('');
      } on KeyMissing catch (e) {
        expect(e.message, equals('OpenSSH Public Key: string is empty'));
      }
    });

    test('extra whitespace ignored', () {
      final pk = OpenSshPublicKey.decode('    a    AAAAAWEAAAABKg==');
      expect(pk.keyType, equals('a'));
    });

    test('base64 missing padding', () {
      try {
        final pk = OpenSshPublicKey.decode('a AAAAAWEAAAABKg'); // missing ==
      } on KeyBad catch (e) {
        expect(e.message, equals('OpenSSH Public Key: base64 invalid'));
      }
    });

    test('base64 has invalid character', () {
      try {
        final pk = OpenSshPublicKey.decode('a AAAAAWEAAAABKg~'); // ~ not base64
      } on KeyBad catch (e) {
        expect(e.message, equals('OpenSSH Public Key: Invalid character'));
      }
    });

    test('base64 ends with a tab rather than a space', () {
      try {
        final pk = OpenSshPublicKey.decode('a AAAAAWEAAAABKg==\t');
      } on KeyBad catch (e) {
        expect(e.message, equals('OpenSSH Public Key: base64 terminated incorrectly'));
      }
    });
  });
}


//----------------------------------------------------------------

void encode() {
  group('encode', () {
    const testCases = {
      'ed25519 AAAAB2VkMjU1MTkAAAABKg==': null,
      'ed25519 AAAAB2VkMjU1MTkAAAABKg== foobar': 'foobar',
      'ed25519 AAAAB2VkMjU1MTkAAAABKg== CR   AND LF   become spaces': 'CR \n AND LF \r become spaces',
    };

    for (final entry in testCases.entries) {
      final expectedEncoding = entry.key;
      final comment = entry.value;

      test('CR and LF in comment become spaces', () {
        const keyType = 'ed25519';

        final k = GenericPublicKey(dataForOpenSshFormat(keyType));
        k.properties.comment = comment;

        final enc = k.encodeOpenSsh();
        expect(enc, startsWith(keyType));
        expect(enc, equals('$expectedEncoding\n'));
      });
    }

  });
}
//================================================================

void main() {
  valid();
  invalid();
  decode();
  encode();
}
