
import 'dart:io';

import 'package:test/test.dart';
import 'package:x509/src/x509_base.dart';

void main() {
  group('csr', () {
    test('ec 384 from pem', () async {
      var pem = await File('test/files/ec384-csr.pem').readAsString();
      var csr = parsePem(pem).single as CertificationRequest;

      expect(csr.signatureAlgorithm.algorithm.name, 'ecdsa-with-SHA256');
    });
    test('rsa from pem', () async {
      var pem = await File('test/files/csr.pem').readAsString();
      var csr = parsePem(pem).single as CertificationRequest;

      expect(csr.signatureAlgorithm.algorithm.name, 'sha256WithRSAEncryption');
    });
    test('ec 384 to pem', () async {
      var pem = await File('test/files/ec384-csr.pem').readAsString();
      var csr = parsePem(pem).single as CertificationRequest;
      var pem2 = asn1ToPem(csr.toAsn1(), PemType.certificateRequest);
    });
    test('rsa to pem', () async {
      var pem = await File('test/files/csr.pem').readAsString();
      var csr = parsePem(pem).single as CertificationRequest;
      var csr2 = CertificationRequest.fromAsn1(csr.toAsn1());
      expect(csr2.signatureAlgorithm.algorithm,
          csr.signatureAlgorithm.algorithm,
          reason: 'signature algo');
      expect(csr2.signature,
          csr.signature,
          reason: 'signature');

      expect(csr2.toAsn1(), csr.toAsn1());

      var pem2 = asn1ToPem(csr.toAsn1(), PemType.certificateRequest);
      var csr3 = parsePem(pem2).single as CertificationRequest;
      expect(csr3.toAsn1(), csr.toAsn1());
    });
  });
}