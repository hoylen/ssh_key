//import 'dart:convert';

//import 'package:test/test.dart';

//import 'package:ssh_keys/ssh_keys.dart';

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
/// Test the generation of new RSA key-pairs.

void groupGenerate() {
/*
  group('generating key pairs', () {
    //----------------------------------------------------------------
    // Generate a new RSA key pair using the default bit length.

    test('default bit length', () {
      final k = generateRsaKeys();
      final pubKey = k.item1;
      final pvtKey = k.item2;

      expect(pubKey.publicKey.exponent, equals(BigInt.from(65537)));
      expect(pubKey.publicKey.modulus.bitLength, equals(2048));

      expect(pvtKey.modulus.bitLength, equals(2048));
      //expect(privateKey.exponent.bitLength, equals(2048 - 2));
      expect(pvtKey.p.bitLength, equals(1024));
      expect(pvtKey.q.bitLength, equals(1024));
    }, skip: defaultSkip);

    //----------------------------------------------------------------
    // Generate a new RSA key pair using an explicitly provided bit length.

    test('explicit bit lengths', () {
      final bitLengths = [512, 1024]; // insecure: do not use in production
      // final bitLengths = [1024, 4096];
      // final bitLengths = [512, 1024, 2048, 4096];

      for (final bitLength in bitLengths) {
        final k = generateRsaKeys(bitLength: bitLength);
        final pubKey = k.item1;
        final pvtKey = k.item2;

        expect(pubKey.publicKey.exponent, equals(BigInt.from(65537)));
        expect(pubKey.publicKey.modulus.bitLength, equals(bitLength));

        expect(pvtKey.modulus.bitLength, equals(bitLength));
        //expect(k.privateKey.exponent.bitLength, equals(2048 - 2));
        expect(pvtKey.p.bitLength, equals(bitLength / 2));
        expect(pvtKey.q.bitLength, equals(bitLength / 2));

        // print('$bitLength-bit RSA key: mod=${pubKey.publicKey.modulus}');
      }
    }, skip: defaultSkip);
  }, skip: true);


 */
}
//================================================================

void main() {
  groupGenerate();
}
