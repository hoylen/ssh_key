import 'dart:convert';

import 'package:test/test.dart';

import 'package:ssh_key/ssh_key.dart';
import 'package:ssh_key/ssh_key_txt.dart';

//----------------------------------------------------------------
/// Default skip value for tests
///
/// To run an individual test, set [defaultSkip] to _true_
/// and explicitly set the skip value of that test to _false_.
///
/// To run all the tests, set the [defaultSkip] to _false_ and remove any
/// explicitly set skip values.

const defaultSkip = false;

//================================================================
// Example RSA key-pair with 2048 bits

final BigInt expectedPublicExponent = BigInt.from(65537);

final BigInt expectedModulus = BigInt.parse(
    '2736307442096091061479976827609422395069467298735352347857561704'
    '8292187044756879516071751152302761045592672634380454645179579389'
    '1247384586211304287995108001875066199715083334074435967556687399'
    '9319251479798914660139787259708209806761757009712728724790482405'
    '7651253377088098786414563575337058691687308109208896589867638426'
    '3597756332186955927783414432681703994818829934909865953936807204'
    '5089374673421283131773432601260236087842470456477527284269529920'
    '9236346457027022908172067250756592121219157754099664357704607422'
    '3041635653669245371585889101126586702622629740303379451510725987'
    '88797008033612889633467715945087208346497');

final BigInt expectedPrivateExponent = BigInt.parse(
    '2012994044673678049760198403795307718288664828630049327055810038'
    '2216323816910499902472913595464745384914773726618320335200620429'
    '4958727940781628906375149031759198112316146799300101947049919428'
    '9167631591246854029163977038196925697139090753456517539837397626'
    '2134975343234333380981817197273686783073991575282489514518778654'
    '0764374481577527357344634545283763678563461581907950912955299734'
    '7232049164384490158450113676636604834650297037761692726902235748'
    '3252673984385902383489131299035550079282377607128917226237346480'
    '4757648317210338130231521085366318380215406736622417638534538031'
    '30986837268331781597679044932297479458497');
/*
final BigInt expectedIqmp = BigInt.parse(
    '7239702280781304217216231585572705415068904405307077145702306775'
    '3152973238567176141417204109325408031818209357399164848084317657'
    '9296791317032991885309216178076645486062316640900446048768987408'
    '1547610126653944606558685229190502740214774447063843297834385337'
    '6292940313576436508755112497634695605824046588723205');
*/
final BigInt expectedP = BigInt.parse(
    '1746818282918629043887570109341783600524931564831424027772183448'
    '1777918484839763741768663354054850249145952922091155437389551311'
    '0186823754121009665820646073047300961788964532376600780354538537'
    '0868715825197050747098270955502374883585770390213253010823493222'
    '04921888825444491698321155427032670343468855826116329');

final BigInt expectedQ = BigInt.parse(
    '1566452257142739545821524601539678379560286550085718375022878215'
    '4451895840557211082760890790929238013479870540283197382620702416'
    '5384805271627128418862280626618037695428297092711952308471296803'
    '3694803404338678296562263369203809906281297904997776540052229579'
    '86559762623534181808705370992757247052692604976255193');

const expectedComment = 'user@example.com';

const expectedFingerprintSha256 =
    'SHA256:fr9vH93A1GMxuHDezEU9QidkhwhmXED9vlKo0XwKJaU';

const expectedFingerprintMd5 =
    'MD5:d0:bf:7d:76:34:ac:d7:6f:cd:07:01:4a:aa:e6:ec:58';

//================================================================
// Encodings of the public key

// The public key in four formats:
// - SSH Public Key (RFC 4716)
// - OpenSSH Public Key (single-line)
// - PKCS #1 (OpenSSH calls this "PEM")
// - X.509 subjectPublicKeyInfo (OpenSSH incorrectly calls this "PKCS8")

const rfc4716 = '''
---- BEGIN SSH2 PUBLIC KEY ----
Comment: "user@example.com"
AAAAB3NzaC1yc2EAAAADAQABAAABAQDYwd6O4Z+STMxTlFCPcN8VAq9ZNKvaQRYbsEDKK0
ydvTxdwt72xRo8supYX1vgDgRpYBhgDy8OPEMLDuk61sXRdbTITFW1B98rUsvvLEYHM4wJ
QnkWZvcyZz79id2H3r75ow+EL6SF4zxrSnJ9Ax09cKN2oM3nQUn0jkaqG4Hb/thbKbF8Sz
evBrcI0Ld4K64Mduc2XQbW2qMikT4xPBtu7bwPuP1XhipZOBcCBnXdrWCZk6pfYtA/aq5E
n7a2JAyglIpEsAIbtSVmj62BgstmSOy/4tQjVinh6IG8y8ixq59GbmC8KP9zUQ3hhLfT/n
qreXpeh039cotUTWJHyVOB
---- END SSH2 PUBLIC KEY ----
''';

const openSshPublic =
    'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDYwd6O4Z+STMxTlFCPcN8VAq9Z'
    'NKvaQRYbsEDKK0ydvTxdwt72xRo8supYX1vgDgRpYBhgDy8OPEMLDuk61sXRdbTI'
    'TFW1B98rUsvvLEYHM4wJQnkWZvcyZz79id2H3r75ow+EL6SF4zxrSnJ9Ax09cKN2'
    'oM3nQUn0jkaqG4Hb/thbKbF8SzevBrcI0Ld4K64Mduc2XQbW2qMikT4xPBtu7bwP'
    'uP1XhipZOBcCBnXdrWCZk6pfYtA/aq5En7a2JAyglIpEsAIbtSVmj62BgstmSOy/'
    '4tQjVinh6IG8y8ixq59GbmC8KP9zUQ3hhLfT/nqreXpeh039cotUTWJHyVOB use'
    'r@example.com'; // this is one single line of text

const pkcs1PemPublic = '''
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA2MHejuGfkkzMU5RQj3DfFQKvWTSr2kEWG7BAyitMnb08XcLe9sUa
PLLqWF9b4A4EaWAYYA8vDjxDCw7pOtbF0XW0yExVtQffK1LL7yxGBzOMCUJ5Fmb3
Mmc+/Yndh96++aMPhC+kheM8a0pyfQMdPXCjdqDN50FJ9I5GqhuB2/7YWymxfEs3
rwa3CNC3eCuuDHbnNl0G1tqjIpE+MTwbbu28D7j9V4YqWTgXAgZ13a1gmZOqX2LQ
P2quRJ+2tiQMoJSKRLACG7UlZo+tgYLLZkjsv+LUI1Yp4eiBvMvIsaufRm5gvCj/
c1EN4YS30/56q3l6XodN/XKLVE1iR8lTgQIDAQAB
-----END RSA PUBLIC KEY-----
''';

const x509spki = '''
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2MHejuGfkkzMU5RQj3Df
FQKvWTSr2kEWG7BAyitMnb08XcLe9sUaPLLqWF9b4A4EaWAYYA8vDjxDCw7pOtbF
0XW0yExVtQffK1LL7yxGBzOMCUJ5Fmb3Mmc+/Yndh96++aMPhC+kheM8a0pyfQMd
PXCjdqDN50FJ9I5GqhuB2/7YWymxfEs3rwa3CNC3eCuuDHbnNl0G1tqjIpE+MTwb
bu28D7j9V4YqWTgXAgZ13a1gmZOqX2LQP2quRJ+2tiQMoJSKRLACG7UlZo+tgYLL
Zkjsv+LUI1Yp4eiBvMvIsaufRm5gvCj/c1EN4YS30/56q3l6XodN/XKLVE1iR8lT
gQIDAQAB
-----END PUBLIC KEY-----
''';

//================================================================
// Encodings of the private key

// The following represent the same above public key (exponent & modulus)
// in different formats.

// The private key in two formats:
// - OpenSSH Private Key (the "new" OpenSSH format)
// - PuTTY Private Key

const openSshPrivate = '''
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEA2MHejuGfkkzMU5RQj3DfFQKvWTSr2kEWG7BAyitMnb08XcLe9sUa
PLLqWF9b4A4EaWAYYA8vDjxDCw7pOtbF0XW0yExVtQffK1LL7yxGBzOMCUJ5Fmb3Mmc+/Y
ndh96++aMPhC+kheM8a0pyfQMdPXCjdqDN50FJ9I5GqhuB2/7YWymxfEs3rwa3CNC3eCuu
DHbnNl0G1tqjIpE+MTwbbu28D7j9V4YqWTgXAgZ13a1gmZOqX2LQP2quRJ+2tiQMoJSKRL
ACG7UlZo+tgYLLZkjsv+LUI1Yp4eiBvMvIsaufRm5gvCj/c1EN4YS30/56q3l6XodN/XKL
VE1iR8lTgQAAA8ghj3mGIY95hgAAAAdzc2gtcnNhAAABAQDYwd6O4Z+STMxTlFCPcN8VAq
9ZNKvaQRYbsEDKK0ydvTxdwt72xRo8supYX1vgDgRpYBhgDy8OPEMLDuk61sXRdbTITFW1
B98rUsvvLEYHM4wJQnkWZvcyZz79id2H3r75ow+EL6SF4zxrSnJ9Ax09cKN2oM3nQUn0jk
aqG4Hb/thbKbF8SzevBrcI0Ld4K64Mduc2XQbW2qMikT4xPBtu7bwPuP1XhipZOBcCBnXd
rWCZk6pfYtA/aq5En7a2JAyglIpEsAIbtSVmj62BgstmSOy/4tQjVinh6IG8y8ixq59Gbm
C8KP9zUQ3hhLfT/nqreXpeh039cotUTWJHyVOBAAAAAwEAAQAAAQEAn3W4WhrH/qP66T3C
KlRZ+SX5g8HI745USlhWwaQrABxYDY4v4xDLpX3mAs9cUq9dNXxZUkm5T1qr47W7hOq9qs
NSFMx7fOtmlYOavcAvYFremW1KkV18W5sy7uh+jdcjXZlE7/TwrwKlzzR8l1U0LJ/x0XKp
J4iTdJM6jygfV4x/2HOuHxEXovoSUutxAejhbHqWiAprhEI7JemFfRC0/HAyKsXbnv9tmn
UH4aOtDsx2RwvCzv1LtGC8tobkm3RSRmrsT/o0zjeS5QCO1AVqImIuYhdv8Ddbf/BvSANg
3kQ+sGvnDO/o+PXtNqXkl15Vbi/bvQRKA+sdzAviCJCOwQAAAIBnGMa/WL/8d0whd5SZVe
7PSa6owdKFTFrB4Y/O7IZMin32nDLJyqBeTWUev6AlWCo1XQ7HZgPUflE/Px2SeoBq+nZE
3JmilHU/KTwoMysgNfB4KO40VUtEgCfEHmLGtOsG3HTZHnEIcmIJwQsvJfRplmVJJVQ8dU
9eq8B1TwuABQAAAIEA+MFThA474/CVBFjao6/7l+LqRWwUVPfmNg7pQbRf8MlGNc3ekXgd
3wtjUlVxNf1JVtcauR38f5ZVDL8Bu2H7emxn1GQFqku4lwVKOIXM2H0WPk2zBcqNMRfZS6
TrQsLZPkzVJvxHVjMAaS2UpA5yY9PsuOYamAWcCGYA8PWk7ukAAACBAN8R+QRjAPiYlOqG
YxDm+Bv0DwNsQ5xDCOHph7znyYNZ8lttxStprye5TuLJoTrfSJjJSN+yh3MeCQD6x4DiMf
tA8uubkmhgbnoKXSfGrkaCUG2R3wB0+9HYih2LN7tCxMfdPGRw4gcqdIlYCSS1XQpYZ+Px
LegbcHLTUOhiglDZAAAAEHVzZXJAZXhhbXBsZS5jb20BAg==
-----END OPENSSH PRIVATE KEY-----
''';

const openSshPrivateExportedByPuTTYgen = '''
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdz
c2gtcnNhAAAAAwEAAQAAAQEA2MHejuGfkkzMU5RQj3DfFQKvWTSr2kEWG7BAyitM
nb08XcLe9sUaPLLqWF9b4A4EaWAYYA8vDjxDCw7pOtbF0XW0yExVtQffK1LL7yxG
BzOMCUJ5Fmb3Mmc+/Yndh96++aMPhC+kheM8a0pyfQMdPXCjdqDN50FJ9I5GqhuB
2/7YWymxfEs3rwa3CNC3eCuuDHbnNl0G1tqjIpE+MTwbbu28D7j9V4YqWTgXAgZ1
3a1gmZOqX2LQP2quRJ+2tiQMoJSKRLACG7UlZo+tgYLLZkjsv+LUI1Yp4eiBvMvI
saufRm5gvCj/c1EN4YS30/56q3l6XodN/XKLVE1iR8lTgQAAA9Al7g6HJe4OhwAA
AAdzc2gtcnNhAAABAQDYwd6O4Z+STMxTlFCPcN8VAq9ZNKvaQRYbsEDKK0ydvTxd
wt72xRo8supYX1vgDgRpYBhgDy8OPEMLDuk61sXRdbTITFW1B98rUsvvLEYHM4wJ
QnkWZvcyZz79id2H3r75ow+EL6SF4zxrSnJ9Ax09cKN2oM3nQUn0jkaqG4Hb/thb
KbF8SzevBrcI0Ld4K64Mduc2XQbW2qMikT4xPBtu7bwPuP1XhipZOBcCBnXdrWCZ
k6pfYtA/aq5En7a2JAyglIpEsAIbtSVmj62BgstmSOy/4tQjVinh6IG8y8ixq59G
bmC8KP9zUQ3hhLfT/nqreXpeh039cotUTWJHyVOBAAAAAwEAAQAAAQEAn3W4WhrH
/qP66T3CKlRZ+SX5g8HI745USlhWwaQrABxYDY4v4xDLpX3mAs9cUq9dNXxZUkm5
T1qr47W7hOq9qsNSFMx7fOtmlYOavcAvYFremW1KkV18W5sy7uh+jdcjXZlE7/Tw
rwKlzzR8l1U0LJ/x0XKpJ4iTdJM6jygfV4x/2HOuHxEXovoSUutxAejhbHqWiApr
hEI7JemFfRC0/HAyKsXbnv9tmnUH4aOtDsx2RwvCzv1LtGC8tobkm3RSRmrsT/o0
zjeS5QCO1AVqImIuYhdv8Ddbf/BvSANg3kQ+sGvnDO/o+PXtNqXkl15Vbi/bvQRK
A+sdzAviCJCOwQAAAIBnGMa/WL/8d0whd5SZVe7PSa6owdKFTFrB4Y/O7IZMin32
nDLJyqBeTWUev6AlWCo1XQ7HZgPUflE/Px2SeoBq+nZE3JmilHU/KTwoMysgNfB4
KO40VUtEgCfEHmLGtOsG3HTZHnEIcmIJwQsvJfRplmVJJVQ8dU9eq8B1TwuABQAA
AIEA+MFThA474/CVBFjao6/7l+LqRWwUVPfmNg7pQbRf8MlGNc3ekXgd3wtjUlVx
Nf1JVtcauR38f5ZVDL8Bu2H7emxn1GQFqku4lwVKOIXM2H0WPk2zBcqNMRfZS6Tr
QsLZPkzVJvxHVjMAaS2UpA5yY9PsuOYamAWcCGYA8PWk7ukAAACBAN8R+QRjAPiY
lOqGYxDm+Bv0DwNsQ5xDCOHph7znyYNZ8lttxStprye5TuLJoTrfSJjJSN+yh3Me
CQD6x4DiMftA8uubkmhgbnoKXSfGrkaCUG2R3wB0+9HYih2LN7tCxMfdPGRw4gcq
dIlYCSS1XQpYZ+PxLegbcHLTUOhiglDZAAAAEHVzZXJAZXhhbXBsZS5jb20BAgME
BQYHCAkK
-----END OPENSSH PRIVATE KEY-----
''';

// The old or original OpenSSH private key file format (unencrypted)

const pkcs1PemPrivate = '''
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA2MHejuGfkkzMU5RQj3DfFQKvWTSr2kEWG7BAyitMnb08XcLe
9sUaPLLqWF9b4A4EaWAYYA8vDjxDCw7pOtbF0XW0yExVtQffK1LL7yxGBzOMCUJ5
Fmb3Mmc+/Yndh96++aMPhC+kheM8a0pyfQMdPXCjdqDN50FJ9I5GqhuB2/7YWymx
fEs3rwa3CNC3eCuuDHbnNl0G1tqjIpE+MTwbbu28D7j9V4YqWTgXAgZ13a1gmZOq
X2LQP2quRJ+2tiQMoJSKRLACG7UlZo+tgYLLZkjsv+LUI1Yp4eiBvMvIsaufRm5g
vCj/c1EN4YS30/56q3l6XodN/XKLVE1iR8lTgQIDAQABAoIBAQCfdbhaGsf+o/rp
PcIqVFn5JfmDwcjvjlRKWFbBpCsAHFgNji/jEMulfeYCz1xSr101fFlSSblPWqvj
tbuE6r2qw1IUzHt862aVg5q9wC9gWt6ZbUqRXXxbmzLu6H6N1yNdmUTv9PCvAqXP
NHyXVTQsn/HRcqkniJN0kzqPKB9XjH/Yc64fERei+hJS63EB6OFsepaICmuEQjsl
6YV9ELT8cDIqxdue/22adQfho60OzHZHC8LO/Uu0YLy2huSbdFJGauxP+jTON5Ll
AI7UBWoiYi5iF2/wN1t/8G9IA2DeRD6wa+cM7+j49e02peSXXlVuL9u9BEoD6x3M
C+IIkI7BAoGBAPjBU4QOO+PwlQRY2qOv+5fi6kVsFFT35jYO6UG0X/DJRjXN3pF4
Hd8LY1JVcTX9SVbXGrkd/H+WVQy/Abth+3psZ9RkBapLuJcFSjiFzNh9Fj5NswXK
jTEX2Uuk60LC2T5M1Sb8R1YzAGktlKQOcmPT7LjmGpgFnAhmAPD1pO7pAoGBAN8R
+QRjAPiYlOqGYxDm+Bv0DwNsQ5xDCOHph7znyYNZ8lttxStprye5TuLJoTrfSJjJ
SN+yh3MeCQD6x4DiMftA8uubkmhgbnoKXSfGrkaCUG2R3wB0+9HYih2LN7tCxMfd
PGRw4gcqdIlYCSS1XQpYZ+PxLegbcHLTUOhiglDZAoGBALE566qWCY1ohoLGW19r
rjCUdpxnWEUBKX8yOHWbcQ84F1GWDxBNJ9sVXfn27eWtQ2cfceaZup+cF5QxMaaz
NFwQiBkF+hNOR4ExP6Ptj/hdhk91RCrIGLf1adc+9G5oLCb6zpIsAxci1xQYaWJI
+K6u+mTxa9kLhhNluR3zpUKhAoGBAI1qLG6OgRAYUte26FjPw9ycxWPLH7WRfbES
Rj4Ix2RhAlbZ6RRThHnvbUYywua6pKBPgsZlvJ7LHLQlR5K6UytQim+5CYDoGUF/
Dn1n5BXJCUndHv2ALCBlYXHHT0aE1pFJ/L5EHdajIIvtZqaB34DueLY1sH+j3Y69
zl30DV9JAoGAZxjGv1i//HdMIXeUmVXuz0muqMHShUxaweGPzuyGTIp99pwyycqg
Xk1lHr+gJVgqNV0Ox2YD1H5RPz8dknqAavp2RNyZopR1Pyk8KDMrIDXweCjuNFVL
RIAnxB5ixrTrBtx02R5xCHJiCcELLyX0aZZlSSVUPHVPXqvAdU8LgAU=
-----END RSA PRIVATE KEY-----''';

const puttyPrivateKey = '''
PuTTY-User-Key-File-2: ssh-rsa
Encryption: none
Comment: user@example.com
Public-Lines: 6
AAAAB3NzaC1yc2EAAAADAQABAAABAQDYwd6O4Z+STMxTlFCPcN8VAq9ZNKvaQRYb
sEDKK0ydvTxdwt72xRo8supYX1vgDgRpYBhgDy8OPEMLDuk61sXRdbTITFW1B98r
UsvvLEYHM4wJQnkWZvcyZz79id2H3r75ow+EL6SF4zxrSnJ9Ax09cKN2oM3nQUn0
jkaqG4Hb/thbKbF8SzevBrcI0Ld4K64Mduc2XQbW2qMikT4xPBtu7bwPuP1XhipZ
OBcCBnXdrWCZk6pfYtA/aq5En7a2JAyglIpEsAIbtSVmj62BgstmSOy/4tQjVinh
6IG8y8ixq59GbmC8KP9zUQ3hhLfT/nqreXpeh039cotUTWJHyVOB
Private-Lines: 14
AAABAQCfdbhaGsf+o/rpPcIqVFn5JfmDwcjvjlRKWFbBpCsAHFgNji/jEMulfeYC
z1xSr101fFlSSblPWqvjtbuE6r2qw1IUzHt862aVg5q9wC9gWt6ZbUqRXXxbmzLu
6H6N1yNdmUTv9PCvAqXPNHyXVTQsn/HRcqkniJN0kzqPKB9XjH/Yc64fERei+hJS
63EB6OFsepaICmuEQjsl6YV9ELT8cDIqxdue/22adQfho60OzHZHC8LO/Uu0YLy2
huSbdFJGauxP+jTON5LlAI7UBWoiYi5iF2/wN1t/8G9IA2DeRD6wa+cM7+j49e02
peSXXlVuL9u9BEoD6x3MC+IIkI7BAAAAgQD4wVOEDjvj8JUEWNqjr/uX4upFbBRU
9+Y2DulBtF/wyUY1zd6ReB3fC2NSVXE1/UlW1xq5Hfx/llUMvwG7Yft6bGfUZAWq
S7iXBUo4hczYfRY+TbMFyo0xF9lLpOtCwtk+TNUm/EdWMwBpLZSkDnJj0+y45hqY
BZwIZgDw9aTu6QAAAIEA3xH5BGMA+JiU6oZjEOb4G/QPA2xDnEMI4emHvOfJg1ny
W23FK2mvJ7lO4smhOt9ImMlI37KHcx4JAPrHgOIx+0Dy65uSaGBuegpdJ8auRoJQ
bZHfAHT70diKHYs3u0LEx908ZHDiByp0iVgJJLVdClhn4/Et6BtwctNQ6GKCUNkA
AACAZxjGv1i//HdMIXeUmVXuz0muqMHShUxaweGPzuyGTIp99pwyycqgXk1lHr+g
JVgqNV0Ox2YD1H5RPz8dknqAavp2RNyZopR1Pyk8KDMrIDXweCjuNFVLRIAnxB5i
xrTrBtx02R5xCHJiCcELLyX0aZZlSSVUPHVPXqvAdU8LgAU=
Private-MAC: 406b9793dfa26a08f9f55c7d104895c42b7cdc79
''';

const puttyPrivateKeyNoComment = '''
PuTTY-User-Key-File-2: ssh-rsa
Encryption: none
Comment: 
Public-Lines: 6
AAAAB3NzaC1yc2EAAAADAQABAAABAQDYwd6O4Z+STMxTlFCPcN8VAq9ZNKvaQRYb
sEDKK0ydvTxdwt72xRo8supYX1vgDgRpYBhgDy8OPEMLDuk61sXRdbTITFW1B98r
UsvvLEYHM4wJQnkWZvcyZz79id2H3r75ow+EL6SF4zxrSnJ9Ax09cKN2oM3nQUn0
jkaqG4Hb/thbKbF8SzevBrcI0Ld4K64Mduc2XQbW2qMikT4xPBtu7bwPuP1XhipZ
OBcCBnXdrWCZk6pfYtA/aq5En7a2JAyglIpEsAIbtSVmj62BgstmSOy/4tQjVinh
6IG8y8ixq59GbmC8KP9zUQ3hhLfT/nqreXpeh039cotUTWJHyVOB
Private-Lines: 14
AAABAQCfdbhaGsf+o/rpPcIqVFn5JfmDwcjvjlRKWFbBpCsAHFgNji/jEMulfeYC
z1xSr101fFlSSblPWqvjtbuE6r2qw1IUzHt862aVg5q9wC9gWt6ZbUqRXXxbmzLu
6H6N1yNdmUTv9PCvAqXPNHyXVTQsn/HRcqkniJN0kzqPKB9XjH/Yc64fERei+hJS
63EB6OFsepaICmuEQjsl6YV9ELT8cDIqxdue/22adQfho60OzHZHC8LO/Uu0YLy2
huSbdFJGauxP+jTON5LlAI7UBWoiYi5iF2/wN1t/8G9IA2DeRD6wa+cM7+j49e02
peSXXlVuL9u9BEoD6x3MC+IIkI7BAAAAgQD4wVOEDjvj8JUEWNqjr/uX4upFbBRU
9+Y2DulBtF/wyUY1zd6ReB3fC2NSVXE1/UlW1xq5Hfx/llUMvwG7Yft6bGfUZAWq
S7iXBUo4hczYfRY+TbMFyo0xF9lLpOtCwtk+TNUm/EdWMwBpLZSkDnJj0+y45hqY
BZwIZgDw9aTu6QAAAIEA3xH5BGMA+JiU6oZjEOb4G/QPA2xDnEMI4emHvOfJg1ny
W23FK2mvJ7lO4smhOt9ImMlI37KHcx4JAPrHgOIx+0Dy65uSaGBuegpdJ8auRoJQ
bZHfAHT70diKHYs3u0LEx908ZHDiByp0iVgJJLVdClhn4/Et6BtwctNQ6GKCUNkA
AACAZxjGv1i//HdMIXeUmVXuz0muqMHShUxaweGPzuyGTIp99pwyycqgXk1lHr+g
JVgqNV0Ox2YD1H5RPz8dknqAavp2RNyZopR1Pyk8KDMrIDXweCjuNFVLRIAnxB5i
xrTrBtx02R5xCHJiCcELLyX0aZZlSSVUPHVPXqvAdU8LgAU=
Private-MAC: 73aa9bbe1b00c5f2c2fdb777dd8d749213f313f3
  ''';

const passPhrase = 'p@ssphr@se';

const puttyPrivateKeyEncrypted = '''
PuTTY-User-Key-File-2: ssh-rsa
Encryption: aes256-cbc
Comment: user@example.com
Public-Lines: 6
AAAAB3NzaC1yc2EAAAADAQABAAABAQDYwd6O4Z+STMxTlFCPcN8VAq9ZNKvaQRYb
sEDKK0ydvTxdwt72xRo8supYX1vgDgRpYBhgDy8OPEMLDuk61sXRdbTITFW1B98r
UsvvLEYHM4wJQnkWZvcyZz79id2H3r75ow+EL6SF4zxrSnJ9Ax09cKN2oM3nQUn0
jkaqG4Hb/thbKbF8SzevBrcI0Ld4K64Mduc2XQbW2qMikT4xPBtu7bwPuP1XhipZ
OBcCBnXdrWCZk6pfYtA/aq5En7a2JAyglIpEsAIbtSVmj62BgstmSOy/4tQjVinh
6IG8y8ixq59GbmC8KP9zUQ3hhLfT/nqreXpeh039cotUTWJHyVOB
Private-Lines: 14
9uYK73IKNjmIiceRpgnTRfYwzz1CLCxY5DcuVbDrgx1NXhuYw029d8YTETUcPZij
KG3PE+WtS7OJcB27MaE4HtFEdfxatewlueR/qGJoH4exG6STDH/7qohwOEsnWuj/
HEcDYalk6gSXRyuAGu5TXfU8r7bymbsPfYglI5R4Fzo1kq8DxUjbInjcrocd9HB5
hT1NDj2uYFZOn7vOGbjtLu8X1AUHe2i25Xlk8KL47ROsmY79KJMVkRZWA9H0GlfG
6qjWDBfBx0ocON/dHNqPW0aedZqnC60FD62NEVfqowoQGRqge4yOuTCCdwCz23Sq
ExE7pP8EVfZ0nL5EMyQTk4nvp7yP6tiHfY+oQB1ciIDWzBM8TEPzuYf6ayfRunIW
xvIdtenSiwstk9MYmtH0yaWoG3KZuhmPz+jWqzttReAsfd+GnJY9ma0SGHelHN2G
O/iWradlfwn2zYEblMShrqqLAfhmOuQ2QpUVoP50htYp5GnyYrkiGuyyuumHYn6s
D7mFUAD/USDOGXuKNswW1Ts0JSgjxMVnYNXZXsQLyDohupJ/hKBnKwxv/HZQJgrU
SgREOJKFtpon7GMGqyOgPNKr5Qch7Yz6TKS4uiMvDlkDC7rh3KNQwd9k/gs8cuoM
vB2nvtvSZ/u1QloHiSLW+UfNdZidKd3Xo0h9FiXQkqMFTPYSUeXS+X+aykGOJisb
7FYxE5aOFo8IoEPQPDj12i/Vdebh6VU1wPKfef+4V8hIKtYypf0cJ6+1nTLT5KYk
XctLV8sDjYn1PeJLDdYwaCXGdfLsAfblIsm4mh1qv4ffZatR/BhkmA3qLV0La/ef
PmgK6xqfHJnuxJ5Q5II14yanE+P9Mn7ZUCpXugHBFvBLtSZVXwNz5mlND7h//DIK
Private-MAC: 3ae77133ea08137a992cd8b2009a0b4ad3c3b0d1
''';

const puttyPrivateKeyEncryptedNoComment = '''
PuTTY-User-Key-File-2: ssh-rsa
Encryption: aes256-cbc
Comment: 
Public-Lines: 6
AAAAB3NzaC1yc2EAAAADAQABAAABAQDYwd6O4Z+STMxTlFCPcN8VAq9ZNKvaQRYb
sEDKK0ydvTxdwt72xRo8supYX1vgDgRpYBhgDy8OPEMLDuk61sXRdbTITFW1B98r
UsvvLEYHM4wJQnkWZvcyZz79id2H3r75ow+EL6SF4zxrSnJ9Ax09cKN2oM3nQUn0
jkaqG4Hb/thbKbF8SzevBrcI0Ld4K64Mduc2XQbW2qMikT4xPBtu7bwPuP1XhipZ
OBcCBnXdrWCZk6pfYtA/aq5En7a2JAyglIpEsAIbtSVmj62BgstmSOy/4tQjVinh
6IG8y8ixq59GbmC8KP9zUQ3hhLfT/nqreXpeh039cotUTWJHyVOB
Private-Lines: 14
9uYK73IKNjmIiceRpgnTRfYwzz1CLCxY5DcuVbDrgx1NXhuYw029d8YTETUcPZij
KG3PE+WtS7OJcB27MaE4HtFEdfxatewlueR/qGJoH4exG6STDH/7qohwOEsnWuj/
HEcDYalk6gSXRyuAGu5TXfU8r7bymbsPfYglI5R4Fzo1kq8DxUjbInjcrocd9HB5
hT1NDj2uYFZOn7vOGbjtLu8X1AUHe2i25Xlk8KL47ROsmY79KJMVkRZWA9H0GlfG
6qjWDBfBx0ocON/dHNqPW0aedZqnC60FD62NEVfqowoQGRqge4yOuTCCdwCz23Sq
ExE7pP8EVfZ0nL5EMyQTk4nvp7yP6tiHfY+oQB1ciIDWzBM8TEPzuYf6ayfRunIW
xvIdtenSiwstk9MYmtH0yaWoG3KZuhmPz+jWqzttReAsfd+GnJY9ma0SGHelHN2G
O/iWradlfwn2zYEblMShrqqLAfhmOuQ2QpUVoP50htYp5GnyYrkiGuyyuumHYn6s
D7mFUAD/USDOGXuKNswW1Ts0JSgjxMVnYNXZXsQLyDohupJ/hKBnKwxv/HZQJgrU
SgREOJKFtpon7GMGqyOgPNKr5Qch7Yz6TKS4uiMvDlkDC7rh3KNQwd9k/gs8cuoM
vB2nvtvSZ/u1QloHiSLW+UfNdZidKd3Xo0h9FiXQkqMFTPYSUeXS+X+aykGOJisb
7FYxE5aOFo8IoEPQPDj12i/Vdebh6VU1wPKfef+4V8hIKtYypf0cJ6+1nTLT5KYk
XctLV8sDjYn1PeJLDdYwaCXGdfLsAfblIsm4mh1qv4ffZatR/BhkmA3qLV0La/ef
PmgK6xqfHJnuxJ5Q5II14yanE+P9Mn7ZUCpXugHBFvBLtSZVXwNz5mlND7h//DIK
Private-MAC: 8245b952c6ee92932b01d76d7f72d94b2be87294
''';

const sshComPrivate = '''
---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----
Comment: "user@example.com"
P2/56wAAA+4AAAA3aWYtbW9kbntzaWdue3JzYS1wa2NzMS1zaGExfSxlbmNyeXB0e3JzYS
1wa2NzMXYyLW9hZXB9fQAAAARub25lAAADnwAAA5sAAAARAQABAAAIAJ91uFoax/6j+uk9
wipUWfkl+YPByO+OVEpYVsGkKwAcWA2OL+MQy6V95gLPXFKvXTV8WVJJuU9aq+O1u4Tqva
rDUhTMe3zrZpWDmr3AL2Ba3pltSpFdfFubMu7ofo3XI12ZRO/08K8Cpc80fJdVNCyf8dFy
qSeIk3STOo8oH1eMf9hzrh8RF6L6ElLrcQHo4Wx6logKa4RCOyXphX0QtPxwMirF257/bZ
p1B+GjrQ7MdkcLws79S7RgvLaG5Jt0UkZq7E/6NM43kuUAjtQFaiJiLmIXb/A3W3/wb0gD
YN5EPrBr5wzv6Pj17Tal5JdeVW4v270ESgPrHcwL4giQjsEAAAgA2MHejuGfkkzMU5RQj3
DfFQKvWTSr2kEWG7BAyitMnb08XcLe9sUaPLLqWF9b4A4EaWAYYA8vDjxDCw7pOtbF0XW0
yExVtQffK1LL7yxGBzOMCUJ5Fmb3Mmc+/Yndh96++aMPhC+kheM8a0pyfQMdPXCjdqDN50
FJ9I5GqhuB2/7YWymxfEs3rwa3CNC3eCuuDHbnNl0G1tqjIpE+MTwbbu28D7j9V4YqWTgX
AgZ13a1gmZOqX2LQP2quRJ+2tiQMoJSKRLACG7UlZo+tgYLLZkjsv+LUI1Yp4eiBvMvIsa
ufRm5gvCj/c1EN4YS30/56q3l6XodN/XKLVE1iR8lTgQAAA/9nGMa/WL/8d0whd5SZVe7P
Sa6owdKFTFrB4Y/O7IZMin32nDLJyqBeTWUev6AlWCo1XQ7HZgPUflE/Px2SeoBq+nZE3J
milHU/KTwoMysgNfB4KO40VUtEgCfEHmLGtOsG3HTZHnEIcmIJwQsvJfRplmVJJVQ8dU9e
q8B1TwuABQAABADfEfkEYwD4mJTqhmMQ5vgb9A8DbEOcQwjh6Ye858mDWfJbbcUraa8nuU
7iyaE630iYyUjfsodzHgkA+seA4jH7QPLrm5JoYG56Cl0nxq5GglBtkd8AdPvR2Iodize7
QsTH3TxkcOIHKnSJWAkktV0KWGfj8S3oG3By01DoYoJQ2QAABAD4wVOEDjvj8JUEWNqjr/
uX4upFbBRU9+Y2DulBtF/wyUY1zd6ReB3fC2NSVXE1/UlW1xq5Hfx/llUMvwG7Yft6bGfU
ZAWqS7iXBUo4hczYfRY+TbMFyo0xF9lLpOtCwtk+TNUm/EdWMwBpLZSkDnJj0+y45hqYBZ
wIZgDw9aTu6Q==
---- END SSH2 ENCRYPTED PRIVATE KEY ----
''';

//================================================================
// Functions to check the parsed values are those that were expected.

//----------------------------------------------------------------
/// Checks the RSA public values are correct.

void checkValuesPublic(RSAPublicKeyWithInfo rsaPub,
    {String? expComment = expectedComment}) {
  expect(rsaPub.modulus!.bitLength, equals(2048));
  expect(rsaPub.exponent!.bitLength, equals(17));

  expect(rsaPub.modulus, equals(expectedModulus));
  expect(rsaPub.exponent, equals(expectedPublicExponent));

  // Comment

  final comments = rsaPub.properties.values(SshPublicKeyHeader.commentTag);
  if (expComment != null) {
    expect(comments, isNotNull, reason: 'expecting comment, none found');
    expect(comments!.length, equals(1), reason: 'too many comments found');
    expect(comments.first, equals(expComment));
  } else {
    expect(comments, isNull, reason: 'not expecting comment, but does exist');
  }

  expect(rsaPub.fingerprint(), equals(expectedFingerprintSha256));
  expect(rsaPub.fingerprint(format: FingerprintType.md5),
      equals(expectedFingerprintMd5));
}

//----------------------------------------------------------------
/// Checks the RSA private (and public) values are correct.

void checkValuesPrivate(RSAPrivateKeyWithInfo rsaPvt,
    {String? expComment = expectedComment}) {
  expect(rsaPvt.modulus!.bitLength, equals(2048));
  expect(rsaPvt.publicExponent!.bitLength, equals(17));
  expect(rsaPvt.privateExponent!.bitLength, equals(2048));
  expect(rsaPvt.p!.bitLength, equals(1024));
  expect(rsaPvt.q!.bitLength, equals(1024));

  expect(rsaPvt.modulus, equals(expectedModulus));
  expect(rsaPvt.publicExponent, equals(expectedPublicExponent));
  expect(rsaPvt.privateExponent, equals(expectedPrivateExponent));
  expect(rsaPvt.p, equals(expectedP));
  expect(rsaPvt.q, equals(expectedQ));

  // RSA numbers have expected properties that make them an RSA key

  expect(rsaPvt.p! * rsaPvt.q!, equals(rsaPvt.modulus));

  final x = BigInt.from(42); // check decrypt(encrypt(x)) == x
  final cipher = x.modPow(rsaPvt.publicExponent!, rsaPvt.modulus!);
  expect(cipher.modPow(rsaPvt.privateExponent!, rsaPvt.modulus!), equals(x),
      reason: 'RSA values are incorrect');

  // Comment matches expected value (or is absent as expected)

  expect(rsaPvt.comment, equals(expComment));
}

//================================================================
// Utility methods

//----------------------------------------------------------------

RSAPublicKeyWithInfo testParse(
    BigInt modulus, BigInt publicExponent, int bitLength, String s) {
  //final container = FormatSsh.parse(s);
  final k = publicKeyDecode(s);

  expect(k, const TypeMatcher<RSAPublicKeyWithInfo>());

  // ignore: avoid_as
  final rsaKey = k as RSAPublicKeyWithInfo;
  expect(rsaKey.source!.encoding, equals(PubKeyEncoding.openSsh));
  expect(rsaKey.modulus, equals(modulus));
  expect(rsaKey.modulus!.bitLength, equals(bitLength));
  expect(rsaKey.exponent, equals(publicExponent));
  final comments = rsaKey.properties.values(SshPublicKeyHeader.commentTag);
  expect(comments!.length, equals(1));
  expect(comments.first, equals(expectedComment));

  return rsaKey;
}

//----------------------------------------------------------------

void badParse(String title, String str, String expectedMessage,
    {bool noKey = false, bool unsupported = false}) {
  test(title, () {
    try {
      testParse(BigInt.zero, BigInt.zero, 2048, str);
      fail('parser did not raise an exception');
    } on KeyMissing catch (e) {
      if (noKey) {
        expect(e.message, equals(expectedMessage));
      } else {
        fail('KeyMissing thrown when expecting a different exception');
      }
    } on KeyBad catch (e) {
      if (!noKey) {
        expect(e.message, equals(expectedMessage), reason: 'noKey: $title');
      } else {
        fail('KeyBad thrown when expecting a different exception');
      }
    } on KeyUnsupported catch (e) {
      if (unsupported) {
        expect(e.message, equals(expectedMessage),
            reason: 'unsupported: $title');
      } else {
        fail('KeyUnsupported thrown when expecting a different exception');
      }
    }
  });
}

//================================================================

void groupPublicDecode() {
  group('decode', () {
    //----------------
    test('SSH Public Key (RFC 4716)', () {
      // Low-level format parse

      final fmt = SshPublicKey.decode(rfc4716);

      expect(fmt.source!.begin, equals(0));
      expect(fmt.source!.end, equals(rfc4716.length));
      final srcTxt = fmt.source;
      if (srcTxt is PubTextSource) {
        expect(srcTxt.encoding, equals(PubKeyEncoding.sshPublicKey));
      } else {
        fail('wrong type for sourceText: ${srcTxt.runtimeType}');
      }

      expect(fmt.headers.length, equals(1));
      expect(fmt.headers[0].tag, equals('Comment')); // case is preserved
      expect(fmt.headers[0].value, equals('"$expectedComment"'));
      // Note: the parsing of RFC 4716 produces a sequence of headers
      // where the case of the header-tag is preserved and the header-values
      // are not changed (i.e. any double quotes around comments are
      // preserved).

      expect(fmt.bytes.length, equals(279));

      // High-level public key parse

      final k = publicKeyDecode(rfc4716);

      expect(k, const TypeMatcher<RSAPublicKeyWithInfo>());
      // ignore: avoid_as
      final rsaPub = k as RSAPublicKeyWithInfo;
      checkValuesPublic(rsaPub);

      expect(rsaPub.source!.begin, equals(0));
      expect(rsaPub.source!.end, equals(rfc4716.length));
      expect(rsaPub.source!.encoding, equals(PubKeyEncoding.sshPublicKey));

      expect(rsaPub.properties.keys.length, equals(1));
      expect(rsaPub.properties.values('commENT')!.length,
          equals(1)); // case insensitive
      expect(
          rsaPub.properties.values('commENT')!.first, equals(expectedComment));
      expect(
          rsaPub.properties.comment, equals(expectedComment)); // case preserved
      // Note: when the RFC 4716 is decoded into a public key, the headers are
      // converted to properties where the case of the header-tags is treated
      // as case-insensitive (but case-preserved from the header-tag) and the
      // header-values are normalised (i.e. any double quotes around comments
      // are removed).
    }, skip: defaultSkip);

    //----------------

    group('OpenSSH Public Key', () {
      //final container = FormatSsh.parse(s);

      test('correct', () {
        final k = publicKeyDecode(openSshPublic);

        expect(k, const TypeMatcher<RSAPublicKeyWithInfo>());
        // ignore: avoid_as
        final rsaPub = k as RSAPublicKeyWithInfo;

        checkValuesPublic(rsaPub);
        expect(rsaPub.source!.str, equals(openSshPublic));
        expect(rsaPub.source!.begin, equals(0));
        expect(rsaPub.source!.end, equals(openSshPublic.length));
        expect(rsaPub.source!.encoding, equals(PubKeyEncoding.openSsh));
      });

      final baseOpenSSH = openSshPublic.replaceAll(' $expectedComment', '');
      test('no comment', () {
        final k = publicKeyDecode(baseOpenSSH);
        // ignore: avoid_as
        checkValuesPublic(k as RSAPublicKeyWithInfo, expComment: null);
      });

      test('empty comment', () {
        final k = publicKeyDecode('$baseOpenSSH ');
        // ignore: avoid_as
        checkValuesPublic(k as RSAPublicKeyWithInfo, expComment: '');
      });

      test('one-space comment', () {
        final k = publicKeyDecode('$baseOpenSSH  ');
        // ignore: avoid_as
        checkValuesPublic(k as RSAPublicKeyWithInfo, expComment: ' ');
      });

      test('two-space comment', () {
        final k = publicKeyDecode('$baseOpenSSH   ');
        // ignore: avoid_as
        checkValuesPublic(k as RSAPublicKeyWithInfo, expComment: '  ');
      });
    });

    //----------------
    test('PKCS #1 Public Key (PEM)', () {
      // Low-level format parse

      final te = TextualEncoding.decode(pkcs1PemPublic);

      expect(te.label, equals('RSA PUBLIC KEY'));

      expect(te.source is TextSource, isTrue); // generic
      expect(te.source is PubTextSource, isFalse);
      expect(te.source is PvtTextSource, isFalse);
      expect(te.source!.begin, equals(0));
      expect(te.source!.end, equals(pkcs1PemPublic.length));

      // High-level public key parse

      final k = publicKeyDecode(pkcs1PemPublic);
      expect(k, const TypeMatcher<RSAPublicKeyWithInfo>());
      // ignore: avoid_as
      final rsaPub = k as RSAPublicKeyWithInfo;

      expect(rsaPub.source is PubTextSource, isTrue);
      expect(rsaPub.source!.begin, equals(0));
      expect(rsaPub.source!.end, equals(pkcs1PemPublic.length));
      expect(rsaPub.source!.encoding, equals(PubKeyEncoding.pkcs1));

      expect(rsaPub.properties.keys.length, equals(0));
      expect(rsaPub.properties.values('commENT'), isNull);
      expect(rsaPub.properties.comment, isNull);

      checkValuesPublic(rsaPub, expComment: null);
      expect(rsaPub.properties.values(SshPublicKeyHeader.commentTag), isNull);
    }, skip: defaultSkip);

    //----------------
    test('X.509 subjectPublicKeyInfo', () {
      // Low-level format parse

      final te = TextualEncoding.decode(x509spki);

      expect(te.label, equals('PUBLIC KEY'));

      expect(te.source is TextSource, isTrue); // generic
      expect(te.source is PubTextSource, isFalse);
      expect(te.source is PvtTextSource, isFalse);
      expect(te.source!.begin, equals(0));
      expect(te.source!.end, equals(x509spki.length));

      // High-level public key parse

      final k = publicKeyDecode(x509spki);
      expect(k, const TypeMatcher<RSAPublicKeyWithInfo>());
      // ignore: avoid_as
      final rsaPub = k as RSAPublicKeyWithInfo;

      expect(rsaPub.source is PubTextSource, isTrue); // specific with encoding
      expect(rsaPub.source!.begin, equals(0));
      expect(rsaPub.source!.end, equals(x509spki.length));
      expect(rsaPub.source!.encoding, equals(PubKeyEncoding.x509spki));

      expect(rsaPub.properties.keys, isEmpty);
      expect(rsaPub.properties.comment, isNull);

      checkValuesPublic(rsaPub, expComment: null);
    }, skip: defaultSkip);

    group('errors detected', () {
      const alg = 'ssh-rsa';
      final algChunk = [0, 0, 0, alg.length] + latin1.encode(alg);

      const wrongAlg = 'ssh-rs';
      final wrongAlgChunk =
          [0, 0, 0, wrongAlg.length] + latin1.encode(wrongAlg);

      final chunk = [0, 0, 0, 1, 42];

      // expect(base64.encode(chunk), equals('AAAAASo='));

      badParse('empty string', '', 'no public key found', noKey: true);
      badParse('no data', 'ssh-rsa', 'OpenSSH Public Key: key-type missing');
      badParse('no data, has space', 'ssh-rsa ',
          'OpenSSH Public Key: base64 missing');

      badParse(
          'bad data', 'ssh-rsa AAAAB3', 'OpenSSH Public Key: base64 invalid');

      // ssh-rsa expects exactly 3 chunks

      badParse('one chunk', '$alg ${base64.encode(algChunk)}',
          'data incomplete (for 32-bit unsigned integer)');

      badParse('two chunks', '$alg ${base64.encode(algChunk + chunk)}',
          'data incomplete (for 32-bit unsigned integer)');

      badParse(
          'four chunks',
          '$alg ${base64.encode(algChunk + chunk + chunk + chunk)}',
          'unexpected extra data in RSA public key');

      // First chunk must match the algorithm

      badParse(
          'algorithm mismatch',
          '$alg ${base64.encode(wrongAlgChunk + chunk + chunk)}',
          'OpenSSH Public Key: algorithm name mismatch');

      // Unknown algorithm

      badParse(
          'unknown algorithm',
          '$wrongAlg ${base64.encode(wrongAlgChunk + chunk + chunk)}',
          'unsupported key-type: $wrongAlg',
          unsupported: true);
    }, skip: defaultSkip);
  }, skip: false);
}

//----------------------------------------------------------------
/*TODO
void groupPublicEncode() {
  group('encode', () {
    final k = publicKeyDecode(rfc4716); // key being encoded

    test('SSH Public Key (RFC 4716)', () {
      // Note: must be first test to reuse the comment in the original key
      final str = k.encode(PubKeyEncoding.sshPublicKey);
      // Note: the lines in the example in RFC4716 "wrap before 72 bytes to meet
      // IETF document requirements", but the implementation makes full use of
      // the requirement that "each line in the file MUST NOT be longer than
      // 72 8-bit bytes excluding line termination characters". So the line
      // breaks need to be ignored for the example to match.
      expect(str.replaceAll('\n', ''), equals(rfc4716.replaceAll('\n', '')));

      final reconstructed = publicKeyDecode(str);
      expect(reconstructed, TypeMatcher<MyRSAPublicKey>());
      final reconstructedRsa = reconstructed as MyRSAPublicKey;

      expect(reconstructedRsa.modulus, equals(k.modulus));
      expect(reconstructedRsa.exponent, equals(k.publicExponent));
    });

    test('OpenSSH Public Key', () {
      k.properties[SshPublicKeyHeader.commentTag].clear(); // clear all comments
      k.propertyAdd(SshPublicKeyHeader.commentTag, expectedComment);

      final str = k.encode(PubKeyEncoding.openSsh);
      expect(str, equals(openSshPublic));

      final reconstructed = publicKeyDecode(str);
      expect(reconstructed, TypeMatcher<KeyPublicRsa>());
      final reconstructedRsa = reconstructed as KeyPublicRsa;

      expect(reconstructedRsa.modulus, equals(k.modulus));
      expect(reconstructedRsa.publicExponent, equals(k.publicExponent));
    });

    test('PKCS #1 (PEM)', () {
      // Note: comments are not supported
      final str = k.encode(PubKeyEncoding.pkcs1);
      expect(str, equals(pkcs1PemPublic));

      final reconstructed = publicKeyDecode(str);
      expect(reconstructed, TypeMatcher<KeyPublicRsa>());
      final reconstructedRsa = reconstructed as KeyPublicRsa;

      expect(reconstructedRsa.modulus, equals(k.modulus));
      expect(reconstructedRsa.publicExponent, equals(k.publicExponent));
    });

    test('X.509 subjectPublicKeyInfo', () {
      // Note: comments are not supported
      final str = k.encode(PubKeyEncoding.x509spki);
      expect(str, equals(x509spki));

      final reconstructed = publicKeyDecode(str);
      expect(reconstructed, TypeMatcher<KeyPublicRsa>());
      final reconstructedRsa = reconstructed as KeyPublicRsa;

      expect(reconstructedRsa.modulus, equals(k.modulus));
      expect(reconstructedRsa.publicExponent, equals(k.publicExponent));
    });
  });
}

 */

//----------------------------------------------------------------

void groupPrivateDecode() {
  group('decode', () {
    test('OpenSSH Private Key', () {
      final pvt = privateKeyDecode(openSshPrivate);
      expect(pvt, isNotNull);

      expect(pvt, const TypeMatcher<RSAPrivateKeyWithInfo>());
      // ignore: avoid_as
      final rsaPvt = pvt as RSAPrivateKeyWithInfo;

      expect(rsaPvt.source is PvtTextSource, isTrue);
      expect(rsaPvt.source!.begin, equals(0));
      expect(rsaPvt.source!.end, equals(openSshPrivate.length));
      expect(rsaPvt.source!.encoding, equals(PvtKeyEncoding.openSsh));

      checkValuesPrivate(rsaPvt);

      // Try the version exported by PuTTYgen

      final pvt2 = privateKeyDecode(openSshPrivateExportedByPuTTYgen);
      expect(pvt2, isNotNull);

      expect(pvt2, const TypeMatcher<RSAPrivateKeyWithInfo>());
      // ignore: avoid_as
      checkValuesPrivate(pvt2 as RSAPrivateKeyWithInfo);
    });

    //----------------

    test('Unencrypted PKCS #1 Private Key', () {
      final pvt = privateKeyDecode(pkcs1PemPrivate);
      expect(pvt, isNotNull);

      expect(pvt, TypeMatcher<RSAPrivateKeyWithInfo>());

      final rsa = pvt as RSAPrivateKeyWithInfo;

      expect(rsa.source!.begin, equals(0));
      expect(rsa.source!.end, equals(pkcs1PemPrivate.length));
      expect(rsa.source!.encoding, equals(PvtKeyEncoding.pkcs1));

      checkValuesPrivate(rsa, expComment: null);
    });

    //----------------

    group('PuTTY Private Key', () {
      test('Unencrypted PPK with comment', () {
        final pvt = privateKeyDecode(puttyPrivateKey);
        expect(pvt, isNotNull);

        expect(pvt, const TypeMatcher<RSAPrivateKeyWithInfo>());
        // ignore: avoid_as
        final rsaPvt = pvt as RSAPrivateKeyWithInfo;

        expect(rsaPvt.source!.begin, equals(0));
        expect(rsaPvt.source!.end, equals(puttyPrivateKey.length));
        expect(rsaPvt.source!.encoding, equals(PvtKeyEncoding.puttyPrivateKey));

        checkValuesPrivate(rsaPvt);
      });

      test('Unencrypted PPK without comment', () {
        final pvt = privateKeyDecode(puttyPrivateKeyNoComment);
        expect(pvt, isNotNull);

        expect(pvt, const TypeMatcher<RSAPrivateKeyWithInfo>());
        // ignore: avoid_as
        final rsaPvt = pvt as RSAPrivateKeyWithInfo;

        expect(rsaPvt.source!.begin, equals(0));
        expect(rsaPvt.source!.end, equals(puttyPrivateKeyNoComment.length));
        expect(rsaPvt.source!.encoding, equals(PvtKeyEncoding.puttyPrivateKey));

        checkValuesPrivate(rsaPvt, expComment: null);
      });

/* Encrypted keys not supported yet
      test('Encrypted PPK with comment', () {
        final pvt = KeyPrivate.decode(puttyPrivateKeyEncrypted);
        expect(pvt, isNotNull);

        expect(pvt, TypeMatcher<KeyPrivateRsa>());

        final rsa = pvt as KeyPrivateRsa;

        expect(rsa.sourceText.begin, equals(0));
        expect(rsa.sourceText.end, equals(puttyPrivateKeyEncrypted.length));
        expect(rsa.sourceText.encoding, equals(PvtKeyEncoding.openSsh));

        checkValuesPrivate(rsa);
      });

      test('Encrypted PPK without comment', () {
        final pvt = KeyPrivate.decode(puttyPrivateKeyEncryptedNoComment);
        expect(pvt, isNotNull);

        expect(pvt, TypeMatcher<KeyPrivateRsa>());
        final rsa = pvt as KeyPrivateRsa;

        expect(rsa.sourceText.begin, equals(0));
        expect(rsa.sourceText.end,
            equals(puttyPrivateKeyEncryptedNoComment.length));
        expect(rsa.sourceText.encoding, equals(PvtKeyEncoding.openSsh));

        checkValuesPrivate(rsa, expComment: null);
      });
*/
    });

    //----------------

/* SSH.com keys not supported yet
    test('SSH.com Private Key', () {
      final pvt = KeyPrivate.decode(sshComPrivate);
      expect(pvt, isNotNull);

      expect(pvt, TypeMatcher<KeyPrivateRsa>());
      final rsa = pvt as KeyPrivateRsa;

      expect(rsa.sourceText.begin, equals(0));
      expect(rsa.sourceText.end, equals(sshComPrivate.length));
    });
       */
  });
}

//----------------------------------------------------------------

void groupPrivateEncode() {
  group('encode', () {
    test('OpenSSH Private Key', () {
      final sourceRsa = RSAPrivateKeyWithInfo(
          expectedModulus, expectedPrivateExponent, expectedP, expectedQ);
      // TODO sourceRsa.comment = expectedComment;

      // Encode it

      final encoding = sourceRsa.encode(PvtKeyEncoding.openSsh);

      // Reconstruct a key from the generated encoding

      final reconstructed = privateKeyDecode(encoding);

      expect(reconstructed, const TypeMatcher<RSAPrivateKeyWithInfo>());
      // ignore: avoid_as
      final reconRsa = reconstructed as RSAPrivateKeyWithInfo;

      // RSA numbers have expected values
      checkValuesPrivate(reconRsa);

      // Line lengths in the base64 encoded content are allowed to be different.
      //
      // The values are different because ssh-keygen produces 70 characters per
      // line, but the Textual Encoding of RFC7468 stipulates that generators
      // produce lines that must wrap the base64-encoded lines so each line,
      // except the last, consists of exactly 64 characters.

      expect(encoding.replaceAll('\n', ''),
          equals(openSshPrivate.replaceAll('\n', '')));
    });

    test('PuTTY Private Key', () {
      // Create a source private key by decoding the example

      final pvt = privateKeyDecode(puttyPrivateKey);
      expect(pvt, const TypeMatcher<RSAPrivateKeyWithInfo>());
      // ignore: avoid_as
      final sourceRsa = pvt as RSAPrivateKeyWithInfo;

      // Encode it

      final encoding = sourceRsa.encode(PvtKeyEncoding.puttyPrivateKey);

      // Reconstruct a key from the generated encoding

      final reconstructed = privateKeyDecode(encoding);
      expect(reconstructed, const TypeMatcher<RSAPrivateKeyWithInfo>());
      // ignore: avoid_as
      final reconRsa = pvt;

      // The reconstructed key should match the source key

      expect(reconRsa.modulus, equals(sourceRsa.modulus));
      expect(reconRsa.publicExponent, equals(sourceRsa.publicExponent));
      expect(reconRsa.privateExponent, equals(sourceRsa.privateExponent));
      expect(reconRsa.p, equals(sourceRsa.p));
      expect(reconRsa.q, equals(sourceRsa.q));
      // TODO expect(reconRsa.comment, equals(sourceRsa.comment));

      // Line lengths in the base64 encoded content are allowed to be different.
      //
      // The values are different because ssh-keygen produces 70 characters per
      // line, but the Textual Encoding of RFC7468 stipulates that generators
      // produce lines that must wrap the base64-encoded lines so each line,
      // except the last, consists of exactly 64 characters.

      expect(encoding.replaceAll('\n', ''),
          equals(puttyPrivateKey.replaceAll('\n', '')));
    });
  });
}

//================================================================

void main() {
  // Normal test

  group('public key formats', () {
    assert(true);
    groupPublicDecode();
    // TODO: groupPublicEncode();
  });
  group('private key formats', () {
    assert(true);
    groupPrivateDecode();
    // TODO: groupPrivateEncode();
  });
}
