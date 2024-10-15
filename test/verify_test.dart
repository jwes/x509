import 'dart:io';
import 'package:asn1lib/asn1lib.dart';
import 'package:test/test.dart';
import 'package:x509/x509.dart' as x509;


void main() {
  test('test verify a single rsa cert from pem', () async {
    /// this is currently the only way that works
    var caPem = await File("test/resources/rsa.ca.cert.pem").readAsString();
    var toCheckPem = await File("test/resources/rsa.toCheck.cert.pem").readAsString();

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
    var caPem = await File("test/resources/ec.ca.cert.pem").readAsString();
    var toCheckPem = await File("test/resources/ec.toCheck.cert.pem").readAsString();
    
    var ca = x509.parsePem(caPem).single as x509.X509Certificate;
    var toCheck = x509.parsePem(toCheckPem).single as x509.X509Certificate;

    var data = x509.pemToDer(toCheckPem).single.$1;
    var asn1Parser = ASN1Parser(data);
    var seq = asn1Parser.nextObject() as ASN1Sequence;
    var verifier = ca.publicKey.createVerifier(x509.algorithms.signing.ecdsa.sha256);

    final bytes = (seq.elements[0] as ASN1Sequence).encodedBytes;
    print('pem    ${bytes.length} ${bytes.sublist(0, 40).map((e) => e.toRadixString(16)).join(', ')}');
    expect(verifier.verify(bytes, toCheck.signature), true);
  });

  test('test verify a single parsed cert', () async {
    var caPem = await File("test/resources/ec.ca.cert.pem").readAsString();
    var toCheckPem = await File("test/resources/ec.toCheck.cert.pem").readAsString();

    var ca = x509.parsePem(caPem).single as x509.X509Certificate;
    var toCheck = x509.parsePem(toCheckPem).single as x509.X509Certificate;
    final all = toCheck.toAsn1().encodedBytes;
    print('all    ${all.length}   ${all.sublist(0, 40).map((e) => e.toRadixString(16)).join(', ')}');
    final bytes = toCheck.tbsCertificate.toAsn1().encodedBytes;
    print('bytes ${bytes.length}  ${bytes.sublist(0, 40).map((e) => e.toRadixString(16)).join(', ')}');
    var verifier = ca.publicKey.createVerifier(x509.algorithms.signing.ecdsa.sha256);
    expect(verifier.verify(bytes, toCheck.signature), true);
  });
}