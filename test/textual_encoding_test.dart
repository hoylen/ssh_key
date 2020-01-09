import 'dart:convert';
import 'dart:typed_data';
//import 'dart:js_util';

import 'package:test/test.dart';
import 'package:asn1lib/asn1lib.dart';

import 'package:ssh_key/ssh_key_txt.dart';
import 'package:ssh_key/ssh_key.dart' show KeyMissing, KeyBad;

//================================================================
/// Example data for use in tests.

final Uint8List exampleData = Uint8List.fromList(utf8.encode('Hello World!'));

//================================================================

void groupEncode() {
  //----------------------------------------------------------------

  group('encoding', () {
    //----------------------------------------------------------------

    group('valid', () {
      //----------------

      test('example', () {
        final te = TextualEncoding('EXAMPLE', exampleData);

        expect(
            te.encode(),
            equals('-----BEGIN EXAMPLE-----\n'
                'SGVsbG8gV29ybGQh\n'
                '-----END EXAMPLE-----\n'));
      });

      //----------------

      test('null data and null label', () {
        final te = TextualEncoding(null, null);

        expect(
            te.encode(),
            equals('-----BEGIN -----\n'
                '-----END -----\n'));
      });

      //----------------

      test('empty data', () {
        final te = TextualEncoding('EMPTY', Uint8List(0));

        expect(
            te.encode(),
            equals('-----BEGIN EMPTY-----\n'
                '-----END EMPTY-----\n'));
      });

      //----------------

      test('blank label', () {
        final te = TextualEncoding('', exampleData);

        expect(
            te.encode(),
            equals('-----BEGIN -----\n'
                'SGVsbG8gV29ybGQh\n'
                '-----END -----\n'));
      });

      //----------------

      test('padding 1', () {
        final te = TextualEncoding('EXAMPLE', Uint8List.fromList([1, 1]));
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
        final te = TextualEncoding('EXAMPLE', Uint8List.fromList([1]));
        // 000000 01.... ...... ......
        //      A      Q      =      =

        expect(
            te.encode(),
            equals('-----BEGIN EXAMPLE-----\n'
                'AQ==\n'
                '-----END EXAMPLE-----\n'));
      });
    });
  });
}

void groupDecode() {
  //----------------------------------------------------------------

  group('decoding', () {
    //----------------------------------------------------------------

    group('valid', () {
      //----------------
      test('empty data', () {
        final te = TextualEncoding.decode(
            '-----BEGIN EXAMPLE----------END EXAMPLE-----');
        expect(te.label, equals('EXAMPLE'));
        expect(te.data, equals(<int>[]));
        expect(te.source.begin, equals(0));
        expect(te.source.end, equals(44));

        expect(te.data.length, equals(0));
      });

      //----------------
      test('no line breaks', () {
        final te = TextualEncoding.decode('''
-----BEGIN EXAMPLE-----${base64.encode(exampleData)}-----END EXAMPLE-----
      ''');
        expect(te.label, equals('EXAMPLE'));
        expect(te.data, equals(exampleData));
        expect(te.source.begin, equals(0));
        expect(te.source.end, equals(61));
      });

      //----------------
      test('text before pre-encoding boundary ignored', () {
        const textWithPreamble = '''
----BEGIN is ignored because there are only 4 hyphens
-----begin is ignored because it is the wrong case
-----BEGINEXAMPLE----- is ignored because there is no space after the BEGIN
This is ignored
-----BEGIN EXAMPLE-----
SGVsbG8gV29ybGQh
-----END EXAMPLE-----
      ''';

        // Throws exception if preamble is not allowed

        try {
          TextualEncoding.decode(textWithPreamble);
          fail('did not throw exception');
        } on KeyMissing catch (e) {
          expect(e.message, equals('no Textual Encoding'));
        }

        // Succeeds if preamble is allowed

        final te =
            TextualEncoding.decode(textWithPreamble, allowPreamble: true);
        expect(te.label, equals('EXAMPLE'));
        expect(te.data, equals(exampleData));
        expect(te.source.begin, equals(197));
        expect(te.source.end, equals(260));
      });

      //----------------
      test('non-base64 characters ignored', () {
        final te = TextualEncoding.decode('''
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
        expect(te.source.begin, equals(0));
        expect(te.source.end, equals(243));
      });
    });

    //----------------------------------------------------------------

    group('invalid', () {
      //----------------
      test('no text throws exception', () {
        try {
          TextualEncoding.decode('');
          fail('did not throw exception');
        } on KeyMissing catch (e) {
          expect(e.message, equals('no Textual Encoding'));
        }
      });

      //----------------
      test('pre-encapsulation boundary does not end with -----', () {
        // has 4 hyphens instead of 5
        try {
          TextualEncoding.decode('''
-----BEGIN EXAMPLE----
SGVsbG8gV29ybGQh
-----END EXAMPLE-----
''');
          fail('did not throw exception');
        } on KeyBad catch (e) {
          expect(e.message, equals('malformed pre-encapsulation boundary'));
        }
      });

      //----------------
      test('missing post-encapsulation bounary', () {
        try {
          TextualEncoding.decode('''
-----BEGIN EXAMPLE-----
SGVsbG8gV29ybGQh
''');
          fail('did not throw exception');
        } on KeyBad catch (e) {
          expect(e.message, equals('missing post-encapsulation boundary'));
        }
      });

      //----------------
      test('post-encapsulation boundary does not end with -----', () {
        // has 4 hyphens instead of 5
        try {
          TextualEncoding.decode('''
-----BEGIN EXAMPLE-----
SGVsbG8gV29ybGQh
-----END EXAMPLE----
''');
          fail('did not throw exception');
        } on KeyBad catch (e) {
          expect(e.message, equals('malformed post-encapsulation boundary'));
        }
      });

      //----------------
      test('bad base-64', () {
        // has 4 hyphens instead of 5
        try {
          TextualEncoding.decode('''
-----BEGIN EXAMPLE-----
SGVsbG8gV29ybGQ
-----END EXAMPLE-----
''');
          fail('did not throw exception');
        } on KeyBad catch (e) {
          expect(e.message, equals('incomplete encapsulated data'));
        }
      });
    });
  });

  //----------------------------------------------------------------

  group('examples from RFC7468', () {
    //----------------
    // Example from section 5.1 of RFC 7468
    // https://tools.ietf.org/html/rfc7468#section-5.1
    test('Certificate encoding (5.1)', () {
      final te = TextualEncoding.decode('''
-----BEGIN CERTIFICATE-----
MIICLDCCAdKgAwIBAgIBADAKBggqhkjOPQQDAjB9MQswCQYDVQQGEwJCRTEPMA0G
A1UEChMGR251VExTMSUwIwYDVQQLExxHbnVUTFMgY2VydGlmaWNhdGUgYXV0aG9y
aXR5MQ8wDQYDVQQIEwZMZXV2ZW4xJTAjBgNVBAMTHEdudVRMUyBjZXJ0aWZpY2F0
ZSBhdXRob3JpdHkwHhcNMTEwNTIzMjAzODIxWhcNMTIxMjIyMDc0MTUxWjB9MQsw
CQYDVQQGEwJCRTEPMA0GA1UEChMGR251VExTMSUwIwYDVQQLExxHbnVUTFMgY2Vy
dGlmaWNhdGUgYXV0aG9yaXR5MQ8wDQYDVQQIEwZMZXV2ZW4xJTAjBgNVBAMTHEdu
dVRMUyBjZXJ0aWZpY2F0ZSBhdXRob3JpdHkwWTATBgcqhkjOPQIBBggqhkjOPQMB
BwNCAARS2I0jiuNn14Y2sSALCX3IybqiIJUvxUpj+oNfzngvj/Niyv2394BWnW4X
uQ4RTEiywK87WRcWMGgJB5kX/t2no0MwQTAPBgNVHRMBAf8EBTADAQH/MA8GA1Ud
DwEB/wQFAwMHBgAwHQYDVR0OBBYEFPC0gf6YEr+1KLlkQAPLzB9mTigDMAoGCCqG
SM49BAMCA0gAMEUCIDGuwD1KPyG+hRf88MeyMQcqOFZD0TbVleF+UsAGQ4enAiEA
l4wOuDwKQa+upc8GftXE2C//4mKANBC6It01gUaTIpo=
-----END CERTIFICATE-----
''');
      expect(te.label, equals('CERTIFICATE'));
      expect(te.data.length, equals(560));

      // Decode the BER encoding

      final p = ASN1Parser(te.data);
      final objects = <ASN1Object>[];
      while (p.hasNext()) {
        objects.add(p.nextObject());
      }

      expect(objects.length, equals(1));

      expect(objects.first, const TypeMatcher<ASN1Sequence>());

      final seq = objects.first;
      if (seq is ASN1Sequence) {
        expect(seq.elements.length, equals(3));

        final s1 = seq.elements[0];
        final s2 = seq.elements[1];
        final s3 = seq.elements[2];

        expect(s1, const TypeMatcher<ASN1Sequence>());
        expect(s1.tag, equals(0x30));

        expect(s2, const TypeMatcher<ASN1Sequence>());
        expect(s2.tag, equals(0x30));

        expect(s3, const TypeMatcher<ASN1BitString>());
        expect(s3.tag, equals(0x03));
        final bytes = s3.contentBytes();
        expect(bytes.length, equals(71));
      } else {
        fail('not an ASN1 Sequence');
      }
    });

    //----------------
    test('Certificate with xplanatory Text (5.2)', () {
      final te = TextualEncoding.decode('''
-----BEGIN CERTIFICATE-----
MIICLDCCAdKgAwIBAgIBADAKBggqhkjOPQQDAjB9MQswCQYDVQQGEwJCRTEPMA0G
A1UEChMGR251VExTMSUwIwYDVQQLExxHbnVUTFMgY2VydGlmaWNhdGUgYXV0aG9y
aXR5MQ8wDQYDVQQIEwZMZXV2ZW4xJTAjBgNVBAMTHEdudVRMUyBjZXJ0aWZpY2F0
ZSBhdXRob3JpdHkwHhcNMTEwNTIzMjAzODIxWhcNMTIxMjIyMDc0MTUxWjB9MQsw
CQYDVQQGEwJCRTEPMA0GA1UEChMGR251VExTMSUwIwYDVQQLExxHbnVUTFMgY2Vy
dGlmaWNhdGUgYXV0aG9yaXR5MQ8wDQYDVQQIEwZMZXV2ZW4xJTAjBgNVBAMTHEdu
dVRMUyBjZXJ0aWZpY2F0ZSBhdXRob3JpdHkwWTATBgcqhkjOPQIBBggqhkjOPQMB
BwNCAARS2I0jiuNn14Y2sSALCX3IybqiIJUvxUpj+oNfzngvj/Niyv2394BWnW4X
uQ4RTEiywK87WRcWMGgJB5kX/t2no0MwQTAPBgNVHRMBAf8EBTADAQH/MA8GA1Ud
DwEB/wQFAwMHBgAwHQYDVR0OBBYEFPC0gf6YEr+1KLlkQAPLzB9mTigDMAoGCCqG
SM49BAMCA0gAMEUCIDGuwD1KPyG+hRf88MeyMQcqOFZD0TbVleF+UsAGQ4enAiEA
l4wOuDwKQa+upc8GftXE2C//4mKANBC6It01gUaTIpo=
-----END CERTIFICATE-----
''');
      expect(te.label, equals('CERTIFICATE'));
      expect(te.data.length, equals(560));
    });

    //----------------
    test('Certificate Revocation List (6)', () {
      final te = TextualEncoding.decode('''
-----BEGIN X509 CRL-----
MIIB9DCCAV8CAQEwCwYJKoZIhvcNAQEFMIIBCDEXMBUGA1UEChMOVmVyaVNpZ24s
IEluYy4xHzAdBgNVBAsTFlZlcmlTaWduIFRydXN0IE5ldHdvcmsxRjBEBgNVBAsT
PXd3dy52ZXJpc2lnbi5jb20vcmVwb3NpdG9yeS9SUEEgSW5jb3JwLiBieSBSZWYu
LExJQUIuTFREKGMpOTgxHjAcBgNVBAsTFVBlcnNvbmEgTm90IFZhbGlkYXRlZDEm
MCQGA1UECxMdRGlnaXRhbCBJRCBDbGFzcyAxIC0gTmV0c2NhcGUxGDAWBgNVBAMU
D1NpbW9uIEpvc2Vmc3NvbjEiMCAGCSqGSIb3DQEJARYTc2ltb25Aam9zZWZzc29u
Lm9yZxcNMDYxMjI3MDgwMjM0WhcNMDcwMjA3MDgwMjM1WjAjMCECEC4QNwPfRoWd
elUNpllhhTgXDTA2MTIyNzA4MDIzNFowCwYJKoZIhvcNAQEFA4GBAD0zX+J2hkcc
Nbrq1Dn5IKL8nXLgPGcHv1I/le1MNo9t1ohGQxB5HnFUkRPAY82fR6Epor4aHgVy
b+5y+neKN9Kn2mPF4iiun+a4o26CjJ0pArojCL1p8T0yyi9Xxvyc/ezaZ98HiIyP
c3DGMNR+oUmSjKZ0jIhAYmeLxaPHfQwR
-----END X509 CRL-----
''');
      expect(te.label, equals('X509 CRL'));
      expect(te.data.length, equals(504));
    });

    //----------------
    test('PKCS #10 Certification Request (7)', () {
      final te = TextualEncoding.decode('''
-----BEGIN CERTIFICATE REQUEST-----
MIIBWDCCAQcCAQAwTjELMAkGA1UEBhMCU0UxJzAlBgNVBAoTHlNpbW9uIEpvc2Vm
c3NvbiBEYXRha29uc3VsdCBBQjEWMBQGA1UEAxMNam9zZWZzc29uLm9yZzBOMBAG
ByqGSM49AgEGBSuBBAAhAzoABLLPSkuXY0l66MbxVJ3Mot5FCFuqQfn6dTs+9/CM
EOlSwVej77tj56kj9R/j9Q+LfysX8FO9I5p3oGIwYAYJKoZIhvcNAQkOMVMwUTAY
BgNVHREEETAPgg1qb3NlZnNzb24ub3JnMAwGA1UdEwEB/wQCMAAwDwYDVR0PAQH/
BAUDAwegADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDATAKBggqhkjOPQQDAgM/ADA8
AhxBvfhxPFfbBbsE1NoFmCUczOFApEuQVUw3ZP69AhwWXk3dgSUsKnuwL5g/ftAY
dEQc8B8jAcnuOrfU
-----END CERTIFICATE REQUEST-----
''');
      expect(te.label, equals('CERTIFICATE REQUEST'));
      expect(te.data.length, equals(348));
    });

    //----------------
    test('PKCS #7 Cryptographic Message Syntax (8)', () {
      final te = TextualEncoding.decode('''
-----BEGIN PKCS7-----
MIHjBgsqhkiG9w0BCRABF6CB0zCB0AIBADFho18CAQCgGwYJKoZIhvcNAQUMMA4E
CLfrI6dr0gUWAgITiDAjBgsqhkiG9w0BCRADCTAUBggqhkiG9w0DBwQIZpECRWtz
u5kEGDCjerXY8odQ7EEEromZJvAurk/j81IrozBSBgkqhkiG9w0BBwEwMwYLKoZI
hvcNAQkQAw8wJDAUBggqhkiG9w0DBwQI0tCBcU09nxEwDAYIKwYBBQUIAQIFAIAQ
OsYGYUFdAH0RNc1p4VbKEAQUM2Xo8PMHBoYdqEcsbTodlCFAZH4=
-----END PKCS7-----
''');
      expect(te.label, equals('PKCS7'));
      expect(te.data.length, equals(230));
    });

    //----------------
    test('Cryptographic Message Syntax (9)', () {
      final te = TextualEncoding.decode('''
-----BEGIN CMS-----
MIGDBgsqhkiG9w0BCRABCaB0MHICAQAwDQYLKoZIhvcNAQkQAwgwXgYJKoZIhvcN
AQcBoFEET3icc87PK0nNK9ENqSxItVIoSa0o0S/ISczMs1ZIzkgsKk4tsQ0N1nUM
dvb05OXi5XLPLEtViMwvLVLwSE0sKlFIVHAqSk3MBkkBAJv0Fx0=
-----END CMS-----
''');
      expect(te.label, equals('CMS'));
      expect(te.data.length, equals(134));
    });

    //----------------
    test(' PKCS #8 private key (10)', () {
      final te = TextualEncoding.decode('''
-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgVcB/UNPxalR9zDYAjQIf
jojUDiQuGnSJrFEEzZPT/92hRANCAASc7UJtgnF/abqWM60T3XNJEzBv5ez9TdwK
H0M6xpM2q+53wmsN/eYLdgtjgBd3DBmHtPilCkiFICXyaA8z9LkJ
-----END PRIVATE KEY-----
''');
      expect(te.label, equals('PRIVATE KEY'));
      expect(te.data.length, equals(135));
    });

    //----------------
    test('PKCS #8 encrypted private key (11)', () {
      final te = TextualEncoding.decode('''
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHNMEAGCSqGSIb3DQEFDTAzMBsGCSqGSIb3DQEFDDAOBAghhICA6T/51QICCAAw
FAYIKoZIhvcNAwcECBCxDgvI59i9BIGIY3CAqlMNBgaSI5QiiWVNJ3IpfLnEiEsW
Z0JIoHyRmKK/+cr9QPLnzxImm0TR9s4JrG3CilzTWvb0jIvbG3hu0zyFPraoMkap
8eRzWsIvC5SVel+CSjoS2mVS87cyjlD+txrmrXOVYDE+eTgMLbrLmsWh3QkCTRtF
QC7k0NNzUHTV9yGDwfqMbw==
-----END ENCRYPTED PRIVATE KEY-----
      ''');
      expect(te.label, equals('ENCRYPTED PRIVATE KEY'));
      expect(te.data.length, equals(208));
    });

    //----------------
    test('Attribute certificate (12)', () {
      final te = TextualEncoding.decode('''
-----BEGIN ATTRIBUTE CERTIFICATE-----
MIICKzCCAZQCAQEwgZeggZQwgYmkgYYwgYMxCzAJBgNVBAYTAlVTMREwDwYDVQQI
DAhOZXcgWW9yazEUMBIGA1UEBwwLU3RvbnkgQnJvb2sxDzANBgNVBAoMBkNTRTU5
MjE6MDgGA1UEAwwxU2NvdHQgU3RhbGxlci9lbWFpbEFkZHJlc3M9c3N0YWxsZXJA
aWMuc3VueXNiLmVkdQIGARWrgUUSoIGMMIGJpIGGMIGDMQswCQYDVQQGEwJVUzER
MA8GA1UECAwITmV3IFlvcmsxFDASBgNVBAcMC1N0b255IEJyb29rMQ8wDQYDVQQK
DAZDU0U1OTIxOjA4BgNVBAMMMVNjb3R0IFN0YWxsZXIvZW1haWxBZGRyZXNzPXNz
dGFsbGVyQGljLnN1bnlzYi5lZHUwDQYJKoZIhvcNAQEFBQACBgEVq4FFSjAiGA8z
OTA3MDIwMTA1MDAwMFoYDzM5MTEwMTMxMDUwMDAwWjArMCkGA1UYSDEiMCCGHmh0
dHA6Ly9pZGVyYXNobi5vcmcvaW5kZXguaHRtbDANBgkqhkiG9w0BAQUFAAOBgQAV
M9axFPXXozEFcer06bj9MCBBCQLtAM7ZXcZjcxyva7xCBDmtZXPYUluHf5OcWPJz
5XPus/xS9wBgtlM3fldIKNyNO8RsMp6Ocx+PGlICc7zpZiGmCYLl64lAEGPO/bsw
Smluak1aZIttePeTAHeJJs8izNJ5aR3Wcd3A5gLztQ==
-----END ATTRIBUTE CERTIFICATE-----
      ''');
      expect(te.label, equals('ATTRIBUTE CERTIFICATE'));
      expect(te.data.length, equals(559));
    });

    //----------------
    test('Public key (13)', () {
      final te = TextualEncoding.decode('''
-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEn1LlwLN/KBYQRVH6HfIMTzfEqJOVztLe
kLchp2hi78cCaMY81FBlYs8J9l7krc+M4aBeCGYFjba+hiXttJWPL7ydlE+5UG4U
Nkn3Eos8EiZByi9DVsyfy9eejh+8AXgp
-----END PUBLIC KEY-----
      ''');
      expect(te.label, equals('PUBLIC KEY'));
      expect(te.data.length, equals(120));

      // Decode the BER/DER encoding

      final p = ASN1Parser(te.data);
      final objects = <ASN1Object>[];
      while (p.hasNext()) {
        objects.add(p.nextObject());
      }

      expect(objects.length, equals(1));

      expect(objects.first, const TypeMatcher<ASN1Sequence>());

      final seq = objects.first;
      if (seq is ASN1Sequence) {
        expect(seq.elements.length, equals(2));

        final s1 = seq.elements[0];
        final s2 = seq.elements[1];

        expect(s1, const TypeMatcher<ASN1Sequence>());
        expect(s1.tag, equals(0x30));

        expect(s2, const TypeMatcher<ASN1BitString>());
        expect(s2.tag, equals(0x03));
      } else {
        fail('not an ASN1 sequence');
      }
    });
  });
}

void main() {
  groupEncode();
  groupDecode();
}
