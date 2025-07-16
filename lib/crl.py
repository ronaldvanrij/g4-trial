from datetime import datetime, timedelta
from cryptography.x509 import ReasonFlags
from cryptography import x509

from .util import force_int
from .keypair import KeyPair


reason_map = {
    "unspecified": ReasonFlags.unspecified,
    "keyCompromise": ReasonFlags.key_compromise,
    "CACompromise": ReasonFlags.ca_compromise,
    "affiliationChanged": ReasonFlags.affiliation_changed,
    "superseded": ReasonFlags.superseded,
    "cessationOfOperation": ReasonFlags.cessation_of_operation,
    "certificateHold": ReasonFlags.certificate_hold,
    "removeFromCRL": ReasonFlags.remove_from_crl,
    "privilegeWithdrawn": ReasonFlags.privilege_withdrawn,
    "AACompromise": ReasonFlags.aa_compromise,
}


def parse_serial_number(input):
    if isinstance(input, str):
        if ':' in input:
            # Assume openSSL output, e.g. '78:74:17:c2:a6:23:5f:55:57:ac:38:5e:e3:4d:6e:82:b4:fd:07:eb'
            return int(input.replace(':', ''), 16)
    return force_int(input)


def generate_crl(revocations: list, ca_keys: KeyPair):

    # Build CRL
    now = datetime.now()
    crl_builder = (
        x509.CertificateRevocationListBuilder()
            .issuer_name(ca_keys.certificate.subject)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_keys.public_key), critical=False)
            .add_extension(x509.CRLNumber(1), critical=False)  # TODO increment CRLNumber with each run
            .last_update(now)
            .next_update(now + timedelta(weeks=52))
    )

    # Create revoked certificate entries
    for revoked_cert in revocations:
        date = revoked_cert.get('date', datetime.now())
        if isinstance(date, str):
            date = datetime.fromisoformat(date)
        crl_reason = reason_map.get(revoked_cert.get('reason', 'unspecified'), ReasonFlags.unspecified)
        revoked_cert = (
            x509.RevokedCertificateBuilder()
                .serial_number(parse_serial_number(revoked_cert['serialNumber']))
                .revocation_date(date)
                .add_extension(x509.CRLReason(crl_reason), critical=False)
                .build()
        )
        crl_builder = crl_builder.add_revoked_certificate(revoked_cert)

    # Sign the CRL (use the same parameters as the signature of the CA's certificate)
    crl = crl_builder.sign(
        private_key=ca_keys.private_key,
        algorithm=ca_keys.certificate.signature_hash_algorithm,
        rsa_padding=ca_keys.certificate.signature_algorithm_parameters
    )

    return crl
