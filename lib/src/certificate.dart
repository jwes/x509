part of x509;

/// A Certificate.
abstract class Certificate {
  /// The public key from this certificate.
  PublicKey get publicKey;
}

/// A X.509 Certificate
class X509Certificate implements Certificate {
  /// The to-be-signed certificate
  final TbsCertificate tbsCertificate;

  ///
  final AlgorithmIdentifier signatureAlgorithm;
  final List<int>? signatureValue;

  @override
  PublicKey get publicKey =>
      tbsCertificate.subjectPublicKeyInfo!.subjectPublicKey;

  const X509Certificate(
      this.tbsCertificate, this.signatureAlgorithm, this.signatureValue);

  /// Creates a certificate from an [ASN1Sequence].
  ///
  /// The ASN.1 definition is:
  ///
  ///   Certificate  ::=  SEQUENCE  {
  ///     tbsCertificate       TBSCertificate,
  ///     signatureAlgorithm   AlgorithmIdentifier,
  ///     signatureValue       BIT STRING  }
  factory X509Certificate.fromAsn1(ASN1Sequence sequence) {
    final algorithm =
        AlgorithmIdentifier.fromAsn1(sequence.elements[1] as ASN1Sequence);
    return X509Certificate(
        TbsCertificate.fromAsn1(sequence.elements[0] as ASN1Sequence),
        algorithm,
        toDart(sequence.elements[2]));
  }

  ASN1Sequence toAsn1() {
    return ASN1Sequence()
      ..add(tbsCertificate.toAsn1())
      ..add(signatureAlgorithm.toAsn1())
      ..add(fromDart(signatureValue));
  }

  @override
  String toString([String prefix = '']) {
    var buffer = StringBuffer();
    buffer.writeln('Certificate: ');
    buffer.writeln('\tData:');
    buffer.writeln(tbsCertificate.toString('\t\t'));
    buffer.writeln('\tSignature Algorithm: $signatureAlgorithm');
    buffer.writeln(toHexString(toBigInt(signatureValue!), '$prefix\t\t', 18));
    return buffer.toString();
  }
  /// return a signature from signatureValue
  Signature get signature {
    ObjectIdentifier name = signatureAlgorithm.algorithm;
    if (name.parent == ObjectIdentifier([1,2,840,10045,4,3])) { // ECDSA with SHA*
      var sig = ASN1Sequence.fromBytes(Uint8List.fromList(signatureValue!)); // x509 DER of r + s
      var r = (sig.elements[0] as ASN1Integer);
      var rb = r.valueBytes();
      if (rb[0] == 0) {
        rb = rb.sublist(1);
      }
      var s = (sig.elements[1] as ASN1Integer);
      var sb = s.valueBytes();
      if (sb[0] == 0) {
        sb = sb.sublist(1);
      }
      Uint8List signature = Uint8List.fromList(rb+sb);
      return Signature(signature);
    } else {
      return Signature(Uint8List.fromList(signatureValue!));
    }
  }

  bool verify(PublicKey publicKey, {bool checkDates=true}) {
    if(checkDates) {
      var validity = tbsCertificate.validity;
      if (validity?.notAfter.isBefore(DateTime.now()) == true) {
        return false;
      }
      if (validity?.notBefore.isAfter(DateTime.now()) == true) {
        return false;
      }
    }
    final bytes = tbsCertificate.toAsn1().encodedBytes;
    // signatureAlgorithm.algorithm.parent
    final name = signatureAlgorithm.algorithm.name;
    Identifier algo = _algorithmFromName(name);
    final verifier = publicKey.createVerifier(algo);
    return verifier.verify(bytes, signature);
  }
}

/// try to get the Identifier from the given name
/// throws an Exception if name did not match a supported algorithm
Identifier _algorithmFromName(String name) {
  switch (name) {
    case 'ecdsa-with-SHA256':
      return algorithms.signing.ecdsa.sha256;
    case 'ecdsa-with-SHA384':
      return algorithms.signing.ecdsa.sha384;
    case 'ecdsa-with-SHA512':
      return algorithms.signing.ecdsa.sha512;
    case 'sha256WithRSAEncryption':
      return algorithms.signing.rsa.sha256;
    case 'sha384WithRSAEncryption':
      return algorithms.signing.rsa.sha384;
    case 'sha512WithRSAEncryption':
    default:
      throw Exception('unsupported signature algorithm $name');
  }
}

/// An unsigned (To-Be-Signed) certificate.
class TbsCertificate {
  /// The version number of the certificate.
  final int? version;

  /// The serial number of the certificate.
  final int? serialNumber;

  /// The signature of the certificate.
  final AlgorithmIdentifier? signature;

  /// The issuer of the certificate.
  final Name? issuer;

  /// The time interval for which this certificate is valid.
  final Validity? validity;

  /// The subject of the certificate.
  final Name? subject;

  final SubjectPublicKeyInfo? subjectPublicKeyInfo;

  /// The issuer unique id.
  final List<int>? issuerUniqueID;

  /// The subject unique id.
  final List<int>? subjectUniqueID;

  /// List of extensions.
  final List<Extension>? extensions;

  const TbsCertificate(
      {this.version,
      this.serialNumber,
      this.signature,
      this.issuer,
      this.validity,
      this.subject,
      this.subjectPublicKeyInfo,
      this.issuerUniqueID,
      this.subjectUniqueID,
      this.extensions});

  /// Creates a to-be-signed certificate from an [ASN1Sequence].
  ///
  /// The ASN.1 definition is:
  ///
  ///   TBSCertificate  ::=  SEQUENCE  {
  ///     version         [0]  EXPLICIT Version DEFAULT v1,
  ///     serialNumber         CertificateSerialNumber,
  ///     signature            AlgorithmIdentifier,
  ///     issuer               Name,
  ///     validity             Validity,
  ///     subject              Name,
  ///     subjectPublicKeyInfo SubjectPublicKeyInfo,
  ///     issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
  ///                          -- If present, version MUST be v2 or v3
  ///     subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
  ///                          -- If present, version MUST be v2 or v3
  ///     extensions      [3]  EXPLICIT Extensions OPTIONAL
  ///                          -- If present, version MUST be v3 }
  ///
  ///   Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
  ///
  ///   CertificateSerialNumber  ::=  INTEGER
  ///
  ///   UniqueIdentifier  ::=  BIT STRING
  ///
  ///   Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
  ///
  factory TbsCertificate.fromAsn1(ASN1Sequence sequence) {
    var elements = sequence.elements;
    var version = 1;
    if (elements.first.tag == 0xa0) {
      var e =
          ASN1Parser(elements.first.valueBytes()).nextObject() as ASN1Integer;
      version = e.valueAsBigInteger.toInt() + 1;
      elements = elements.skip(1).toList();
    }
    var optionals = elements.skip(6);
    Uint8List? iUid, sUid;
    List<Extension>? ex;
    for (var o in optionals) {
      if (o.tag >> 6 == 2) {
        // context
        switch (o.tag & 0x1f) {
          case 1:
            iUid = o.contentBytes();
            break;
          case 2:
            sUid = o.contentBytes();
            break;
          case 3:
            ex = (ASN1Parser(o.contentBytes()).nextObject() as ASN1Sequence)
                .elements
                .map((v) => Extension.fromAsn1(v as ASN1Sequence))
                .toList();
            break;
        }
      }
    }

    return TbsCertificate(
        version: version,
        serialNumber: (elements[0] as ASN1Integer).valueAsBigInteger.toInt(),
        signature: AlgorithmIdentifier.fromAsn1(elements[1] as ASN1Sequence),
        issuer: Name.fromAsn1(elements[2] as ASN1Sequence),
        validity: Validity.fromAsn1(elements[3] as ASN1Sequence),
        subject: Name.fromAsn1(elements[4] as ASN1Sequence),
        subjectPublicKeyInfo:
            SubjectPublicKeyInfo.fromAsn1(elements[5] as ASN1Sequence),
        issuerUniqueID: iUid,
        subjectUniqueID: sUid,
        extensions: ex);
  }

  ASN1Sequence toAsn1() {
    var seq = ASN1Sequence();

    if (version != 1) {
      var v = ASN1Integer(BigInt.from(version! - 1));
      var o = ASN1Object.preEncoded(0xa0, v.encodedBytes);
      var b = o.encodedBytes
        ..setRange(o.encodedBytes.length - v.encodedBytes.length,
            o.encodedBytes.length, v.encodedBytes);
      o = ASN1Object.fromBytes(b);
      seq.add(o);
    }
    seq
      ..add(fromDart(serialNumber))
      ..add(signature!.toAsn1())
      ..add(issuer!.toAsn1())
      ..add(validity!.toAsn1())
      ..add(subject!.toAsn1())
      ..add(subjectPublicKeyInfo!.toAsn1());
    if (version! > 1) {
      if (issuerUniqueID != null) {
        var iuid = ASN1BitString.fromBytes(Uint8List.fromList(issuerUniqueID!));
        seq.add(ASN1Object.preEncoded(0x1f | 1 << 6, iuid.encodedBytes));
      }
      if (subjectUniqueID != null) {
        var suid = ASN1BitString.fromBytes(Uint8List.fromList(subjectUniqueID!));
        seq.add(ASN1Object.preEncoded(0x1f | 2 << 6, suid.encodedBytes));
      }
      if (extensions != null) {
        var exSeq = ASN1Sequence();
        for (var ex in extensions!) {
          exSeq.add(ex.toAsn1());
        }
        seq.add(ASN1Object.preEncoded(0xa3, exSeq.encodedBytes));
      }
    }
    return seq;
  }

  @override
  String toString([String prefix = '']) {
    var buffer = StringBuffer();
    buffer.writeln('${prefix}Version: $version');
    buffer.writeln('${prefix}Serial Number: $serialNumber');
    buffer.writeln('${prefix}Signature Algorithm: $signature');
    buffer.writeln('${prefix}Issuer: $issuer');
    buffer.writeln('${prefix}Validity:');
    buffer.writeln(validity?.toString('$prefix\t') ?? '');
    buffer.writeln('${prefix}Subject: $subject');
    buffer.writeln('${prefix}Subject Public Key Info:');
    buffer.writeln(subjectPublicKeyInfo?.toString('$prefix\t') ?? '');
    if (extensions != null && extensions!.isNotEmpty) {
      buffer.writeln('${prefix}X509v3 extensions:');
      for (var e in extensions!) {
        buffer.writeln(e.toString('$prefix\t'));
      }
    }
    return buffer.toString();
  }
}
