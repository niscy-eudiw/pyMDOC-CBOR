import base64
import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn), x509.NameAttribute(NameOID.COUNTRY_NAME, "FC")])


def make_certificate(subject_key, cn, issuer_key=None, issuer_cn=None, ca=False, days=(-1, 365)):
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(_name(issuer_cn or cn))
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + datetime.timedelta(days=days[0]))
        .not_valid_after(now + datetime.timedelta(days=days[1]))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .sign(issuer_key or subject_key, hashes.SHA256())
    )


def cose_private_key(private_key):
    """pycose dict form of an EC P-256 private key (as the issuer backend builds it)."""
    return {
        "KTY": "EC2",
        "CURVE": "P_256",
        "ALG": "ES256",
        "D": private_key.private_numbers().private_value.to_bytes(32, "big"),
        "KID": b"test-issuer",
    }


def pem_device_key(public_key):
    """Device key as the issuer backend passes it: base64url of a PEM public key."""
    pem = public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.urlsafe_b64encode(pem).decode()


class Pki:
    def __init__(self):
        self.iaca_key = ec.generate_private_key(ec.SECP256R1())
        self.iaca = make_certificate(self.iaca_key, "Test IACA", ca=True)
        self.ds_key = ec.generate_private_key(ec.SECP256R1())
        self.ds = make_certificate(self.ds_key, "Test DS", self.iaca_key, "Test IACA")
        self.device_key = ec.generate_private_key(ec.SECP256R1())

    def write_ds(self, path):
        path.write_bytes(self.ds.public_bytes(serialization.Encoding.DER))
        return str(path)


@pytest.fixture
def pki():
    return Pki()


@pytest.fixture
def validity():
    now = datetime.datetime.now(datetime.timezone.utc)
    return {"issuance_date": now, "expiry_date": now + datetime.timedelta(days=30)}
