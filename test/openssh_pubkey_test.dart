import 'package:test/test.dart';

import 'package:ssh_key/ssh_key.dart';
import 'package:ssh_key/ssh_key_txt.dart';

//================================================================

void parsingValidInput() {
  // Test the parsing of the OpenSSH Public Key format for key-types other
  // than RSA.

  group('valid input:', () {
    const expectedComment = 'foobar';

    const testCases = [
      'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDYwd6O4Z+STMxTlFCPcN8VAq9Z'
          'NKvaQRYbsEDKK0ydvTxdwt72xRo8supYX1vgDgRpYBhgDy8OPEMLDuk61sXRdbTI'
          'TFW1B98rUsvvLEYHM4wJQnkWZvcyZz79id2H3r75ow+EL6SF4zxrSnJ9Ax09cKN2'
          'oM3nQUn0jkaqG4Hb/thbKbF8SzevBrcI0Ld4K64Mduc2XQbW2qMikT4xPBtu7bwP'
          'uP1XhipZOBcCBnXdrWCZk6pfYtA/aq5En7a2JAyglIpEsAIbtSVmj62BgstmSOy/'
          '4tQjVinh6IG8y8ixq59GbmC8KP9zUQ3hhLfT/nqreXpeh039cotUTWJHyVOB'
          ' $expectedComment',
      'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFBIM/P7TiMwEctaIyinciGfVoEx'
          '6I6WNAB9p9qq2vLR $expectedComment',
      'ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAy'
          'NTYAAABBBHAIaMo7ahdKQjMkCnk261n+FPGjtHqswZMlXJirLYlGHI6cDlfVQKGJ'
          'uxSvJsQQWMf0/lTFOWXwjmO0uY+97Pk= $expectedComment',
      'ssh-dss AAAAB3NzaC1kc3MAAACBAMhraVi6eNoOXuDNiv0BTOAEAhh+0uVZ5suy'
          '3TiqEX6zvfBzaR9SrrNEMS6aGH3MSHSJCyQV3MAdXyIoBsFVNjl8/hiBXhyWxNwz'
          'JYPaBRb7+Hd4GGGJ44pX3lNsnWgqlfIKnO0X1/sc5wCNkxlbLAeo9+2Z2EmdCLFK'
          'pyf0FFfpAAAAFQD0tYkCUP3OmZT4ep89YP2hNIbV1wAAAIEArrwl5Yx1nAAL5FNp'
          'HsuzF0MZLXPttpM5pWDKoFweRCT2svL8xU/olRz1dkiQEuEDqreOK6g8Sv7rjsj8'
          'rHq64XZcVSIL9OUoSc8fcKPW1rm8E1lYU1wWA6EKGrhJn056hc6OLE5rXQMsqx5j'
          'C0+YNRpE+qFUp8AXxEtqtf2a7gMAAACBAI/ghZD0l2IAwJcxNzafJ5bkG934sXIc'
          '0FegOhdFxL1BWUCZphnOFgKYKEixKTphUE/FhXLpqhlRj/bc3ySPKnk3y7unQ/7l'
          '1f1MOg3yBxSWH8Fi/RVl/YoYRiGYnMEc3MVUyrz/Ed/QFsX/iU8l+PWIuhPY3Ao8'
          'BxHHffN3PIVU $expectedComment',
    ];

    for (final testCase in testCases) {
      final keyType = RegExp('[^ ]+').firstMatch(testCase)!.group(0);
      group(keyType, () {
        // Can parse it as an OpenSSH public key format (syntax)

        test('syntax parsing', () {
          final k = OpenSshPublicKey.decode(testCase);
          expect(k.keyType, equals(keyType));
          expect(k.data.length, greaterThan(0));

          expect(k.comment, equals(expectedComment));

          expect(k.source?.begin, equals(0));
          expect(k.source?.end, equals(testCase.length));
          expect(k.source?.encoding, equals(PubKeyEncoding.openSsh));
        });

        // Can parse it using the generic public key parsing function

        test('semantic parsing', () {
          final pubKey = publicKeyDecode(testCase);
          if (pubKey is RSAPublicKeyWithInfo) {
            // RSA
            expect(pubKey.properties.comment, equals(expectedComment));

            expect(pubKey.source?.begin, equals(0));
            expect(pubKey.source?.end, equals(testCase.length));
            expect(pubKey.source?.encoding, equals(PubKeyEncoding.openSsh));
          } else if (pubKey is GenericPublicKey) {
            expect(pubKey.keyType, equals(keyType));

            expect(pubKey.properties.comment, equals(expectedComment));

            expect(pubKey.source?.begin, equals(0));
            expect(pubKey.source?.end, equals(testCase.length));
            expect(pubKey.source?.encoding, equals(PubKeyEncoding.openSsh));
          } else {
            fail('Unexpected type of public key: ${pubKey.runtimeType}');
          }
        });
      });
    }
  });
}

//----------------------------------------------------------------

void parsingInvalidInput() {
  group('invalid input', () {});
}

//================================================================

void main() {
  parsingValidInput();
  parsingInvalidInput();
}
