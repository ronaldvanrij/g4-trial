import pathlib
import re
import os
import argparse
from jschon import create_catalog, JSON, JSONSchema
from lib.dn import postprocess_yaml
from lib.util import load_yaml, force_int, get_hash_algo, output_errors
from lib.keypair import KeyPair
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import UnrecognizedExtension
from cryptography.x509.oid import ObjectIdentifier
from asn1crypto.core import Sequence, ObjectIdentifier as Asn1OID, SequenceOf


def parse_oid(oid_or_dict):
    if isinstance(oid_or_dict, dict):
        return ObjectIdentifier(oid_or_dict["oid"])
    return ObjectIdentifier(oid_or_dict)


def build_qc_statements_extension(qc_data):
    """
    Encodes a single QCStatement with a statementId and statementInfo (OID).
    """

    class SemanticsInformation(Sequence):
        _fields = [
            ('semanticsIdentifier', Asn1OID)
        ]

    class QCStatement(Sequence):
        _fields = [
            ('statementId', Asn1OID),
            ('statementInfo', SemanticsInformation)
        ]

    class QCStatements(SequenceOf):
        _child_spec = QCStatement

    semantics_oid = qc_data['value']['value'].split()[0]  # Strip description
    qc = QCStatements([
        QCStatement({
            'statementId': qc_data['value']['oid'],
            'statementInfo': SemanticsInformation({'semanticsIdentifier': semantics_oid})
        })
    ])

    # Return as UnrecognizedExtension to include it
    return UnrecognizedExtension(
        ObjectIdentifier('1.3.6.1.5.5.7.1.3'),  # id-pe-qcStatements
        qc.dump()
    )


def handle_extensions(builder, ext, subject_keys, ca_keys):

    if 'basicConstraints' in ext:
        builder = builder.add_extension(
            x509.BasicConstraints(
                ca=ext['basicConstraints']['cA'],
                path_length=ext['basicConstraints'].get('pathLenConstraint')
            ),
            critical=ext['basicConstraints'].get('critical', True)
        )

    if 'authorityKeyIdentifier' in ext:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_keys.public_key),
            critical=ext['authorityKeyIdentifier'].get('critical', False)
        )

    if 'authorityInfoAccess' in ext:
        aia = ext['authorityInfoAccess']
        access_descriptions = []
        if 'caIssuers' in aia:
            access_descriptions.append(x509.AccessDescription(
                x509.AuthorityInformationAccessOID.CA_ISSUERS,
                x509.UniformResourceIdentifier(aia['caIssuers'])
            ))
            builder = builder.add_extension(
                x509.AuthorityInformationAccess(access_descriptions),
                critical=aia.get('critical', False)
            )

    if 'certificatePolicies' in ext:
        policies = []
        for policy in ext['certificatePolicies']['value']:
            policies.append(x509.PolicyInformation(
                policy_identifier=ObjectIdentifier(policy['oid']),
                policy_qualifiers=None
            ))
        builder = builder.add_extension(
            x509.CertificatePolicies(policies),
            critical=ext['certificatePolicies'].get('critical', False)
        )

    if 'extendedKeyUsage' in ext:
        ekus = []
        for entry in ext['extendedKeyUsage']['value']:
            oid = entry.get('oid') if isinstance(entry, dict) else entry
            ekus.append(ObjectIdentifier(oid))
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(ekus),
            critical=ext['extendedKeyUsage'].get('critical', False)
        )

    if 'cRLDistributionPoints' in ext:
        uris = ext['cRLDistributionPoints'].get('value', [])
        points = [
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(uri)],
                relative_name=None,
                reasons=None,
                crl_issuer=None
            )
            for uri in uris
        ]
        builder = builder.add_extension(
            x509.CRLDistributionPoints(points),
            critical=ext['cRLDistributionPoints'].get('critical', False)
        )

    if 'subjectKeyIdentifier' in ext:
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(subject_keys.public_key),
            critical=ext['subjectKeyIdentifier'].get('critical', False)
        )

    if 'keyUsage' in ext:
        usage_flags = ext['keyUsage']['value']
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature='digitalSignature' in usage_flags,
                content_commitment='nonRepudiation' in usage_flags,
                key_encipherment='keyEncipherment' in usage_flags,
                data_encipherment='dataEncipherment' in usage_flags,
                key_agreement='keyAgreement' in usage_flags,
                key_cert_sign='keyCertSign' in usage_flags,
                crl_sign='cRLSign' in usage_flags,
                encipher_only='encipherOnly' in usage_flags,
                decipher_only='decipherOnly' in usage_flags
            ),
            critical=ext['keyUsage'].get('critical', True)
        )

    if 'subjectAltNames' in ext:
        san_entries = ext['subjectAltNames'].get('value', [])
        dns_names = [x509.DNSName(name) for name in san_entries]
        builder = builder.add_extension(
            x509.SubjectAlternativeName(dns_names),
            critical=ext['subjectAltNames'].get('critical', False)
        )

    if 'qcStatements' in ext:
        qc_ext = build_qc_statements_extension(ext['qcStatements'])
        builder = builder.add_extension(qc_ext, critical=ext['qcStatements'].get('critical', False))

    return builder


def sign(profile, csr, subject_keys, issuer_keys):

    # Validity
    if profile['validity']['notBefore'] == 'now':
        not_before = datetime.now()
    else: # assume date time format
        not_before = datetime.fromisoformat(profile['validity']['notBefore'])

    match = re.match("^([0-9]+)d$", profile['validity']['notAfter'])
    if match:
        # last second is inclusive, therefore substract one second
        not_after = not_before + timedelta(days=int(match.group(1))) - timedelta(seconds=1)
    else: # assume date time format
        not_after = datetime.fromisoformat(profile['validity']['not_after'])

    # Generate a random Serial number
    serial_number = int.from_bytes(os.urandom(20), "big") >> 1

    # Hash algorithm
    hash_algo = get_hash_algo(profile['hashAlgorithm'])

    # Certificate Builder
    builder = x509.CertificateBuilder()
    try:
        builder = builder.subject_name(csr['subject'].as_name())
    except Exception as e:
        print(csr['subject'])
        raise e
    builder = builder.issuer_name(profile['issuer'].as_name())
    builder = builder.public_key(subject_keys.public_key)
    builder = builder.serial_number(serial_number)
    builder = builder.not_valid_before(not_before)
    builder = builder.not_valid_after(not_after)

    # Extensions
    builder = handle_extensions(builder, profile['extensions'], subject_keys, issuer_keys)

    # Sign certificate
    cert = builder.sign(
        private_key=issuer_keys.private_key,
        algorithm=hash_algo,
        rsa_padding=padding.PSS(
            mgf=padding.MGF1(hash_algo),
            salt_length=force_int(profile.get('saltLength', 64))
        )
    )

    subject_keys.certificate = cert

    return cert


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('profile', help="YAML Certificate profile filename")
    parser.add_argument('csrs', nargs='+', help="YAML Certificate Signing Requests to be signed")
    args = parser.parse_args()

    profile = load_yaml(args.profile)
    postprocess_yaml(profile)

    # Validate all CSRs first
    for csrfile in args.csrs:
        csr = load_yaml(csrfile)

        # Validate CSR against the certificate profile
        if 'validations' in profile:
            catalog = create_catalog("2020-12")
            schema = JSONSchema(profile['validations'])
            instance = JSON(csr)
            result = schema.evaluate(instance)
            if not result.valid:
                print(f"CSR {csrfile} is invalid for profile {args.profile[0]} ❌")
                output_errors(result.output("detailed")["errors"])
                exit(1)
        else:
            print(f'WARN: no validation for CSR {csrfile}')

    # Then process the CSRs against the specified certificate profile
    for csrfile in args.csrs:
        csr = load_yaml(csrfile)
        postprocess_yaml(csr)

        selfsigned = profile['issuer'] == csr['subject']

        # Find issuer keypair by name
        issuername = profile['issuer'].generate_basename()
        issuerKeys = KeyPair(issuername)
        try:
            issuerKeys.load()
        except FileNotFoundError:
            if selfsigned:
                issuerKeys.generate_private_key(profile)
            else:
                print(f"Cannot find keys of {issuerKeys} for signing operation, please generate it first")
                exit(1)

        if selfsigned:
            subjectKeys = issuerKeys
        else:
            # Find cert private key - use the same name as the input YAML file
            basename = pathlib.Path(csrfile).stem
            subjectKeys = KeyPair(basename)
            try:
                subjectKeys.load()
            except FileNotFoundError:
                subjectKeys.generate_private_key(profile)

        cert = sign(profile, csr, subjectKeys, issuerKeys)

        # Write issued certificate to disk
        filename = subjectKeys.certificatefile
        with open(filename, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.DER))

        print(f"Certificate issued and saved to {filename}")
