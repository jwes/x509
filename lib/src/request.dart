part of x509;

/// https://tools.ietf.org/html/rfc2986
class CertificationRequest {
  final CertificationRequestInfo certificationRequestInfo;
  final AlgorithmIdentifier signatureAlgorithm;
  final Uint8List signature;

  CertificationRequest(
      this.certificationRequestInfo, this.signatureAlgorithm, this.signature);

  /// CertificationRequest ::= SEQUENCE {
  ///   certificationRequestInfo CertificationRequestInfo,
  ///   signatureAlgorithm AlgorithmIdentifier{{ SignatureAlgorithms }},
  ///   signature          BIT STRING
  /// }
  factory CertificationRequest.fromAsn1(ASN1Sequence sequence) {
    final algorithm = AlgorithmIdentifier.fromAsn1(sequence.elements[1] as ASN1Sequence);
    return CertificationRequest(
        CertificationRequestInfo.fromAsn1(sequence.elements[0] as ASN1Sequence),
        algorithm,
        (sequence.elements[2] as ASN1BitString).contentBytes());
  }

  ASN1Sequence toAsn1() {
    return ASN1Sequence()
        ..add(certificationRequestInfo.toAsn1())
        ..add(signatureAlgorithm.toAsn1())
        ..add(ASN1BitString.fromBytes(signature));
  }
}

class CertificationRequestInfo {
  final int? version;
  final Name subject;
  final SubjectPublicKeyInfo subjectPublicKeyInfo;
  final ASN1Object attributes;

  CertificationRequestInfo(
      this.version, this.subject, this.subjectPublicKeyInfo, this.attributes);

  /// CertificationRequestInfo ::= SEQUENCE {
  ///   version       INTEGER { v1(0) } (v1,...),
  ///   subject       Name,
  ///   subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
  ///   attributes    [0] Attributes{{ CRIAttributes }}
  /// }
  factory CertificationRequestInfo.fromAsn1(ASN1Sequence sequence) {
    return CertificationRequestInfo(
        toDart(sequence.elements[0]).toInt() + 1,
        Name.fromAsn1(sequence.elements[1] as ASN1Sequence),
        SubjectPublicKeyInfo.fromAsn1(sequence.elements[2] as ASN1Sequence),
        sequence.elements[3]);
  }

  ASN1Sequence toAsn1() {
    return ASN1Sequence()
        ..add(fromDart(version))
        ..add(subject.toAsn1())
        ..add(subjectPublicKeyInfo.toAsn1())
        ..add(attributes);
  }
}
