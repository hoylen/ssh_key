//import 'dart:js_util';

import 'package:test/test.dart';

import 'package:ssh_key/ssh_key.dart';
import 'package:ssh_key/ssh_key_bin.dart';
import 'package:ssh_key/ssh_key_txt.dart';

//final exampleData = utf8.encode('Hello World!');

void groupEncode() {
  //----------------------------------------------------------------
/*

  group('encoding', () {
    //----------------------------------------------------------------
    group('valid', () {
      //----------------

      test('example', () {
        final te = Rfc4716SshKeyFormat(exampleData);

        expect(
            te.encode(),
            equals('-----BEGIN EXAMPLE-----\n'
                'SGVsbG8gV29ybGQh\n'
                '-----END EXAMPLE-----\n'));
      });

      //----------------

      test('empty data', () {
        final te = Rfc4716SshKeyFormat(<int>[]);

        expect(
            te.encode(),
            equals('-----BEGIN EMPTY-----\n'
                '-----END EMPTY-----\n'));
      });

      //----------------

      test('blank label', () {
        final te = Rfc4716SshKeyFormat(exampleData);

        expect(
            te.encode(),
            equals('-----BEGIN -----\n'
                'SGVsbG8gV29ybGQh\n'
                '-----END -----\n'));
      });

      //----------------

      test('padding 1', () {
        final te = Rfc4716SshKeyFormat([1, 1]);
        // 000000 010000 0001.. ......
        //      A      Q      E      =

        expect(
            te.encode(),
            equals('-----BEGIN EXAMPLE-----\n'
                'AQE=\n'
                '-----END EXAMPLE-----\n'));
      });

      //----------------

      test('padding 2', () {
        final te = Rfc4716SshKeyFormat([1]);
        // 000000 01.... ...... ......
        //      A      Q      =      =

        expect(
            te.encode(),
            equals('-----BEGIN EXAMPLE-----\n'
                'AQ==\n'
                '-----END EXAMPLE-----\n'));
      });
    });

    //----------------------------------------------------------------

    group('invalid', () {
      //----------------
      test('data null', () {
        try {
          final te = Rfc4716SshKeyFormat(null);
          te.encode();
          fail('did not throw exception');
        } on StateError catch (e) {
          expect(e.message, equals('data is null'));
        }
      });
    });
  });

 */
}

void groupDecode() {
  //----------------------------------------------------------------

  group('decoding', () {
    //----------------------------------------------------------------
/*
    group('valid', () {
      //----------------
      test('empty data', () {
        final te = Rfc4716SshKeyFormat.decode(
            '-----BEGIN EXAMPLE----------END EXAMPLE-----');
        expect(te.label, equals('EXAMPLE'));
        expect(te.data, equals(<int>[]));
        expect(te.offsetBegin, equals(0));
        expect(te.offsetEnd, equals(44));

        var objects = te.asn1;
        expect(objects.length, equals(0));
      });

      //----------------
      test('no line breaks', () {
        final te = Rfc4716SshKeyFormat.decode('''
-----BEGIN EXAMPLE-----SGVsbG8gV29ybGQh-----END EXAMPLE-----
      ''');
        expect(te.label, equals('EXAMPLE'));
        expect(te.data, equals(exampleData));
        expect(te.offsetBegin, equals(0));
        expect(te.offsetEnd, equals(60));

        try {
          var _objects = te.asn1;
          fail('did not throw exception');
        } on BadEncoding catch (e) {
          expect(e.message, equals('not valid ASN.1 BER'));
        }
      });

      //----------------
      test('text before pre-encoding boundary ignored', () {
        final te = Rfc4716SshKeyFormat.decode('''
----BEGIN is ignored because there are only 4 hyphens
-----begin is ignored because it is the wrong case
-----BEGINEXAMPLE----- is ignored because there is no space after the BEGIN
This is ignored
-----BEGIN EXAMPLE-----
SGVsbG8gV29ybGQh
-----END EXAMPLE-----
      ''');
        expect(te.label, equals('EXAMPLE'));
        expect(te.data, equals(exampleData));
        expect(te.offsetBegin, equals(197));
        expect(te.offsetEnd, equals(259));
      });

      //----------------
      test('non-base64 characters ignored', () {
        final te = Rfc4716SshKeyFormat.decode('''
-----BEGIN EXAMPLE-----
SGVs....bG8g
\t \n \r \b
     !   "   #   \$  %   &   '
 (   )   *       ,   -   .    
         :   ;   <       >   ?
 @
             [   \   ]   ^   _
 `
             {   |   }   ~
     V29y
-----
bGQh
-----END EXAMPLE-----
      ''');
        expect(te.label, equals('EXAMPLE'));
        expect(te.data, equals(exampleData));
        expect(te.offsetBegin, equals(0));
        expect(te.offsetEnd, equals(242));
      });
    });
*/
    //----------------------------------------------------------------

    group('invalid', () {
      //----------------
      test('no text', () {
        try {
          SshPublicKey.decode('');
          fail('did not throw exception');
        } on KeyBad catch (e) {
          expect(e.message, equals('no RFC 7468 encoding found'));
        }
      });

      //----------------
      test('missing post-encapsulation bounary', () {
        try {
          SshPublicKey.decode('''
---- BEGIN SSH2 PUBLIC KEY ----
SGVsbG8gV29ybGQh
''');
          fail('did not throw exception');
        } on KeyBad catch (e) {
          expect(e.message, equals('missing end marker'));
        }
      });

      //----------------
      test('no data', () {
        try {
          SshPublicKey.decode('''
---- BEGIN SSH2 PUBLIC KEY ----
---- END SSH2 PUBLIC KEY ----
''');
          fail('did not throw exception');
        } on KeyBad catch (e) {
          expect(e.message, equals('no data'));
        }
      });

      //----------------
      test('bad base-64', () {
        // has 4 hyphens instead of 5
        try {
          SshPublicKey.decode('''
---- BEGIN SSH2 PUBLIC KEY ----
SGVsbG8gV29ybGQ
---- END SSH2 PUBLIC KEY ----
''');
          fail('did not throw exception');
        } on KeyBad catch (e) {
          expect(e.message, equals('incomplete encapsulated data'));
        }
      });
    });
  }, skip: false);

  //----------------------------------------------------------------

  group('examples from RFC 4716', () {
    // Examples from section 3.6 of RFC 4716
    // https://tools.ietf.org/html/rfc4716#section-3.6

    //----------------
    test('example 1', () {
      const text = '''
---- BEGIN SSH2 PUBLIC KEY ----
   Comment: "1024-bit RSA, converted from OpenSSH by me@example.com"
   x-command: /home/me/bin/lock-in-guest.sh
   AAAAB3NzaC1yc2EAAAABIwAAAIEA1on8gxCGJJWSRT4uOrR13mUaUk0hRf4RzxSZ1zRb
   YYFw8pfGesIFoEuVth4HKyF8k1y4mRUnYHP1XNMNMJl1JcEArC2asV8sHf6zSPVffozZ
   5TT4SfsUu/iKy9lUcCfXzwre4WWZSXXcPff+EHtWshahu3WzBdnGxm5Xoi89zcE=
---- END SSH2 PUBLIC KEY ----
''';

      const expectedComment =
          '1024-bit RSA, converted from OpenSSH by me@example.com';

      // Low-level format parse

      final te = SshPublicKey.decode(text);

      expect(te.headers.length, equals(2));

      final h1 = te.headers[0];
      expect(h1.tag, equals('Comment')); // case is preserved
      expect(h1.value, equals('"$expectedComment"')); // quotes kept

      final h2 = te.headers[1];
      expect(h2.tag, equals('x-command'));
      expect(h2.value, equals('/home/me/bin/lock-in-guest.sh'));

      final br = BinaryRange(te.bytes);
      expect(br.nextString(), equals('ssh-rsa'));
      expect(br.nextMPInt().toInt(), equals(35));
      expect(br.nextMPInt().bitLength, equals(1024));
      expect(br.isEmpty, isTrue);

      // High-level public key parse

      final k = publicKeyDecode(text);

      expect(k, const TypeMatcher<RSAPublicKeyWithInfo>());
      // ignore: avoid_as
      final rsaPubKey = k as RSAPublicKeyWithInfo;

      expect(rsaPubKey.source!.encoding, equals(PubKeyEncoding.sshPublicKey));
      expect(rsaPubKey.source!.begin, equals(0));
      expect(rsaPubKey.source!.end, equals(text.length));

      final comments =
          rsaPubKey.properties.values(SshPublicKeyHeader.commentTag);
      expect(comments!.length, equals(1));
      expect(comments.first, equals(expectedComment)); // quotes removed

      final xCommand = rsaPubKey.properties.values('X-Command');
      expect(xCommand!.length, equals(1));
      expect(xCommand.first, equals('/home/me/bin/lock-in-guest.sh'));

      expect(rsaPubKey.exponent, equals(BigInt.from(35)));
      expect(
          rsaPubKey.modulus,
          equals(BigInt.parse(
              '1506544156786113090295958183030487373710969856545671229530617891'
              '9587297919987194532455281332523534171129459102101689885541337121'
              '2667716904887561029697073572592666924988593846209859236305256627'
              '5012119432551936500158787579703733747076222121032278299589022502'
              '20510561975760452406862672017677173961232012344675777')));
    });

    //----------------
    test('example 2', () {
      const text = '''
---- BEGIN SSH2 PUBLIC KEY ----
Comment: This is my public key for use on \\
servers which I don't like.
AAAAB3NzaC1kc3MAAACBAPY8ZOHY2yFSJA6XYC9HRwNHxaehvx5wOJ0rzZdzoSOXxbET
W6ToHv8D1UJ/z+zHo9Fiko5XybZnDIaBDHtblQ+Yp7StxyltHnXF1YLfKD1G4T6JYrdH
YI14Om1eg9e4NnCRleaqoZPF3UGfZia6bXrGTQf3gJq2e7Yisk/gF+1VAAAAFQDb8D5c
vwHWTZDPfX0D2s9Rd7NBvQAAAIEAlN92+Bb7D4KLYk3IwRbXblwXdkPggA4pfdtW9vGf
J0/RHd+NjB4eo1D+0dix6tXwYGN7PKS5R/FXPNwxHPapcj9uL1Jn2AWQ2dsknf+i/FAA
vioUPkmdMc0zuWoSOEsSNhVDtX3WdvVcGcBq9cetzrtOKWOocJmJ80qadxTRHtUAAACB
AN7CY+KKv1gHpRzFwdQm7HK9bb1LAo2KwaoXnadFgeptNBQeSXG1vO+JsvphVMBJc9HS
n24VYtYtsMu74qXviYjziVucWKjjKEb11juqnF0GDlB3VVmxHLmxnAz643WK42Z7dLM5
sY29ouezv4Xz2PuMch5VGPP+CDqzCM4loWgV
---- END SSH2 PUBLIC KEY ----
''';
      const expectedComment =
          "This is my public key for use on servers which I don't like.";

      // Low-level format parse

      final te = SshPublicKey.decode(text);

      expect(te.headers.length, equals(1));

      final h1 = te.headers[0];
      expect(h1.tag, equals('Comment')); // case is preserved
      expect(h1.value, equals(expectedComment)); // had no quotes in encoding

      final br = BinaryRange(te.bytes);
      expect(br.nextString(), equals('ssh-dss'));
      expect(br.nextMPInt().bitLength, equals(1024)); // p
      expect(br.nextMPInt().bitLength, equals(160)); // q
      expect(br.nextMPInt().bitLength, equals(1024)); // g
      expect(br.nextMPInt().bitLength, equals(1024)); // y
      expect(br.isEmpty, isTrue);

      // High-level public key parse

      // final k = publicKeyDecode(text);
      // expect(k, TypeMatcher<PublicKeyDsaSSH>());

      // TODO: implement support for DSA (ssh-dss)
    });

    //----------------
    test('example 3', () {
      const text = '''
---- BEGIN SSH2 PUBLIC KEY ----
Comment: DSA Public Key for use with MyIsp
AAAAB3NzaC1kc3MAAACBAPY8ZOHY2yFSJA6XYC9HRwNHxaehvx5wOJ0rzZdzoSOXxbET
W6ToHv8D1UJ/z+zHo9Fiko5XybZnDIaBDHtblQ+Yp7StxyltHnXF1YLfKD1G4T6JYrdH
YI14Om1eg9e4NnCRleaqoZPF3UGfZia6bXrGTQf3gJq2e7Yisk/gF+1VAAAAFQDb8D5c
vwHWTZDPfX0D2s9Rd7NBvQAAAIEAlN92+Bb7D4KLYk3IwRbXblwXdkPggA4pfdtW9vGf
J0/RHd+NjB4eo1D+0dix6tXwYGN7PKS5R/FXPNwxHPapcj9uL1Jn2AWQ2dsknf+i/FAA
vioUPkmdMc0zuWoSOEsSNhVDtX3WdvVcGcBq9cetzrtOKWOocJmJ80qadxTRHtUAAACB
AN7CY+KKv1gHpRzFwdQm7HK9bb1LAo2KwaoXnadFgeptNBQeSXG1vO+JsvphVMBJc9HS
n24VYtYtsMu74qXviYjziVucWKjjKEb11juqnF0GDlB3VVmxHLmxnAz643WK42Z7dLM5
sY29ouezv4Xz2PuMch5VGPP+CDqzCM4loWgV
---- END SSH2 PUBLIC KEY ----
''';
      const expectedComment = 'DSA Public Key for use with MyIsp';

      // Low-level format parse

      final te = SshPublicKey.decode(text);

      expect(te.headers.length, equals(1));

      final h1 = te.headers[0];
      expect(h1.tag, equals('Comment')); // case is preserved
      expect(h1.value, equals(expectedComment)); // had no quotes in encoding

      final br = BinaryRange(te.bytes);
      expect(br.nextString(), equals('ssh-dss'));
      expect(br.nextMPInt().bitLength, equals(1024)); // p
      expect(br.nextMPInt().bitLength, equals(160)); // q
      expect(br.nextMPInt().bitLength, equals(1024)); // g
      expect(br.nextMPInt().bitLength, equals(1024)); // y
      expect(br.isEmpty, isTrue);

      // High-level public key parse

      // final k = publicKeyDecode(text);
      //expect(k, TypeMatcher<PublicKeyDsaSSH>());

      // TODO: implement support for DSA (ssh-dss)
    });

    //----------------
    test('example 4', () {
      const text = '''
---- BEGIN SSH2 PUBLIC KEY ----
Subject: me
Comment: 1024-bit rsa, created by me@example.com Mon Jan 15 \\
08:31:24 2001
AAAAB3NzaC1yc2EAAAABJQAAAIEAiPWx6WM4lhHNedGfBpPJNPpZ7yKu+dnn1SJejgt4
596k6YjzGGphH2TUxwKzxcKDKKezwkpfnxPkSMkuEspGRt/aZZ9wa++Oi7Qkr8prgHc4
soW6NUlfDzpvZK2H5E7eQaSeP3SAwGmQKUFHCddNaP0L+hM7zhFNzjFvpaMgJw0=
---- END SSH2 PUBLIC KEY ----
''';

      const expectedComment =
          '1024-bit rsa, created by me@example.com Mon Jan 15 08:31:24 2001';

      // Low-level format parse

      final te = SshPublicKey.decode(text);

      expect(te.source!.begin, equals(0));
      expect(te.source!.end, equals(text.length));
      expect(te.source!.encoding, equals(PubKeyEncoding.sshPublicKey));

      expect(te.headers.length, equals(2));
      expect(te.headers[0].tag, equals('Subject')); // case is preserved
      expect(te.headers[0].value, equals('me'));
      expect(te.headers[1].tag, equals('Comment')); // case is preserved
      expect(te.headers[1].value, equals(expectedComment));

      final br = BinaryRange(te.bytes);
      expect(br.nextString(), equals('ssh-rsa'));
      expect(br.nextMPInt().toInt(), equals(37));
      expect(br.nextMPInt().bitLength, equals(1024));
      expect(br.isEmpty, isTrue);

      // High-level public key parse

      final k = publicKeyDecode(text);

      expect(k, const TypeMatcher<RSAPublicKeyWithInfo>());
      // ignore: avoid_as
      final rsaPub = k as RSAPublicKeyWithInfo;

      expect(rsaPub.source!.begin, equals(0));
      expect(rsaPub.source!.end, equals(text.length));
      expect(rsaPub.source!.encoding, equals(PubKeyEncoding.sshPublicKey));

      expect(rsaPub.properties.keys.length, equals(2));
      final comments = rsaPub.properties.values(SshPublicKeyHeader.commentTag);
      expect(comments!.length, equals(1));
      expect(comments.first, equals(expectedComment));
      final subjects = rsaPub.properties.values('SUBJECT');
      expect(subjects!.length, equals(1));
      expect(subjects.first, equals('me'));

      expect(rsaPub.exponent, equals(BigInt.from(37)));
      expect(
          rsaPub.modulus,
          equals(BigInt.parse(
              '9617640432684760117818599046843604287525548752746841141375584372'
              '8698242307899910430682575828149354939234459800667262172822404922'
              '2786686688163066938948405879085356858026368102800879451771654804'
              '8740181718657697984467296611229400707432221385742029615230261053'
              '6517790254815765064094716521557232020618624102311693')));
    });
  });
}

void main() {
  //group_encode();
  groupDecode();
}
