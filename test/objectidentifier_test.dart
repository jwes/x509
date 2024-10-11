import 'package:test/test.dart';
import 'package:x509/x509.dart';

void main() {
  group('name', () {
    test('return correct name', () {
      var oid = ObjectIdentifier([2, 5, 4, 3]);
      expect(oid.name, 'commonName');
    });

    test('throw UnknownOIDNameError when unknown oid', () {
      var oid = ObjectIdentifier([1, 2, 3, 4, 5, 6]);
      expect(() => oid.name, throwsA(TypeMatcher<UnknownOIDNameError>()));
    });
  });
  group('asn.1', () {
    test('test asn.1 encode and decode', () async {
      var oid = ObjectIdentifier([2, 5, 4, 3]);
      var asn1 = oid.toAsn1();
      var oid2 = ObjectIdentifier.fromAsn1(asn1);
      expect(oid2.name, oid.name);
    });
  });
}