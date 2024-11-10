import 'dart:io';
import 'package:asn1lib/asn1lib.dart';
import 'package:test/test.dart';
import 'package:x509/x509.dart' as x509;

void main() {
  test('test verify a single rsa cert from pem', () async {
    /// this is currently the only way that works
    var caPem = await File('test/resources/rsa.ca.cert.pem').readAsString();
    var toCheckPem = await File('test/resources/rsa.toCheck.cert.pem').readAsString();

    var ca = x509.parsePem(caPem).single as x509.X509Certificate;
    var toCheck = x509.parsePem(toCheckPem).single as x509.X509Certificate;

    var data = x509.pemToDer(toCheckPem).single.$1;
    var asn1Parser = ASN1Parser(data);
    var seq = asn1Parser.nextObject() as ASN1Sequence;
    var verifier = ca.publicKey.createVerifier(x509.algorithms.signing.rsa.sha256);

    final bytes = (seq.elements[0] as ASN1Sequence).encodedBytes;
    expect(verifier.verify(bytes, toCheck.signature), true);
  });
  test('test verify a single ec cert from pem', () async {
    /// this is currently the only way that works
    var caPem = await File('test/resources/ec.ca.cert.pem').readAsString();
    var toCheckPem = await File('test/resources/ec.toCheck.cert.pem').readAsString();
    
    var ca = x509.parsePem(caPem).single as x509.X509Certificate;
    var toCheck = x509.parsePem(toCheckPem).single as x509.X509Certificate;

    var data = x509.pemToDer(toCheckPem).single.$1;
    var asn1Parser = ASN1Parser(data);
    var seq = asn1Parser.nextObject() as ASN1Sequence;
    var verifier = ca.publicKey.createVerifier(x509.algorithms.signing.ecdsa.sha256);

    final bytes = (seq.elements[0] as ASN1Sequence).encodedBytes;
    expect(verifier.verify(bytes, toCheck.signature), true);
  });

  test('test verify a single parsed rsa cert', () async {
    var caPem = await File('test/resources/rsa.ca.cert.pem').readAsString();
    var toCheckPem = await File('test/resources/rsa.toCheck.cert.pem').readAsString();

    var ca = x509.parsePem(caPem).single as x509.X509Certificate;
    var toCheck = x509.parsePem(toCheckPem).single as x509.X509Certificate;
    expect(toCheck.verify(ca.publicKey), true);
  });
  test('test verify a single parsed ec cert', () async {
    var caPem = await File('test/resources/ec.ca.cert.pem').readAsString();
    var toCheckPem = await File('test/resources/ec.toCheck.cert.pem').readAsString();

    var ca = x509.parsePem(caPem).single as x509.X509Certificate;
    var toCheck = x509.parsePem(toCheckPem).single as x509.X509Certificate;
    expect(toCheck.verify(ca.publicKey), true);
  });
  test('test verify a single parsed ed448 cert', () async {
    var caPem = await File('test/resources/ed448.ca.cert.pem').readAsString();
    var toCheckPem = await File('test/resources/ed448.toCheck.cert.pem').readAsString();

    // publicKey will not be accepted
    expect(() => x509.parsePem(caPem).single, throwsA(isA<UnimplementedError>()));
    expect(() => x509.parsePem(toCheckPem).single, throwsA(isA<UnimplementedError>()));
  });}