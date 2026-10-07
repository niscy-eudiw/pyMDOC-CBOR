import datetime
import logging
from typing import Iterable, Optional, Union

import cbor2
import cryptography
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from pycose.keys import EC2Key
from pycose.messages import Sign1Message

from pymdoccbor import settings
from pymdoccbor.exceptions import MsoX509ChainNotFound, UnsupportedMsoDataFormat
from pymdoccbor.tools import bytes2CoseSign1, cborlist2CoseSign1

logger = logging.getLogger("pymdoccbor")

X5CHAIN = 33


def load_trusted_certificate(cert: Union[x509.Certificate, bytes, str]) -> x509.Certificate:
    """A trust anchor given as a certificate object, DER or PEM."""
    if isinstance(cert, x509.Certificate):
        return cert
    if isinstance(cert, str):
        cert = cert.encode()
    if cert.lstrip().startswith(b"-----BEGIN"):
        return x509.load_pem_x509_certificate(cert)
    return x509.load_der_x509_certificate(cert)


def _valid_at(cert: x509.Certificate, when: datetime.datetime) -> bool:
    utc = datetime.timezone.utc
    # cryptography < 42 only has the naive (UTC) properties
    before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=utc)
    after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=utc)
    return before <= when <= after


def _issued_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        cert.verify_directly_issued_by(issuer)
        return True
    except Exception:
        return False


class MsoVerifier:
    """
    Parameters
        data: CBOR TAG 24

    Example:
        MsoParser(mdoc['documents'][0]['issuerSigned']['issuerAuth'])

    Note
        The signature is contained in an untagged COSE_Sign1
        structure as defined in RFC 8152.
    """

    def __init__(self, data: cbor2.CBORTag):
        self._data = data
        # not used
        if isinstance(self._data, bytes):
            self.object: Sign1Message = bytes2CoseSign1(
                cbor2.dumps(cbor2.CBORTag(18, value=self._data)))
        elif isinstance(self._data, list):
            self.object: Sign1Message = cborlist2CoseSign1(self._data)
        else:
            raise UnsupportedMsoDataFormat(
                f"MsoParser only supports raw bytes and list, a {type(data)} was provided"
            )

        self.object.key: Optional[EC2Key] = None
        self.public_key: Optional[ec.EllipticCurvePublicKey] = None
        self.x509_certificates: list = []

    @property
    def payload_as_cbor(self):
        """
        return the decoded payload
        """
        return cbor2.loads(self.object.payload)

    @property
    def payload_as_raw(self):
        return self.object.payload

    @property
    def payload_as_dict(self):
        return cbor2.loads(
            cbor2.loads(self.object.payload).value
        )

    @property
    def raw_public_keys(self) -> list:
        """
            the DER certificates of the x5chain header (label 33), leaf first,
            from the protected or the unprotected header
        """
        for headers in (self.object.phdr, self.object.uhdr):
            for h, v in headers.items():
                if getattr(h, "identifier", h) == X5CHAIN:
                    return list(v) if isinstance(v, list) else [v]

        raise MsoX509ChainNotFound(
            "I can't find any valid X509certs, identified by label number 33, "
            "in this MSO."
        )

    def load_public_key(self):
        self.x509_certificates = [
            cryptography.x509.load_der_x509_certificate(i) for i in self.raw_public_keys
        ]

        self.public_key = self.x509_certificates[0].public_key()
        if not isinstance(self.public_key, ec.EllipticCurvePublicKey):
            raise UnsupportedMsoDataFormat("The issuer certificate does not hold an EC key")
        curve = self.public_key.curve.name
        if curve not in settings.COSEKEY_HAZMAT_CRV_MAP:
            raise UnsupportedMsoDataFormat(f"Unsupported issuer key curve: {curve}")
        size = settings.CRV_LEN_MAP[curve]
        numbers = self.public_key.public_numbers()
        self.object.key = EC2Key(
            crv=settings.COSEKEY_HAZMAT_CRV_MAP[curve],
            x=numbers.x.to_bytes(size, "big"),
            y=numbers.y.to_bytes(size, "big"),
        )

    def verify_chain(
        self,
        trusted_certificates: Iterable[Union[x509.Certificate, bytes, str]],
        at_time: Optional[datetime.datetime] = None,
    ) -> bool:
        """
            The x5chain is valid at at_time (default: now), each certificate is
            issued by the next one, and the chain contains or is issued by one
            of the trusted certificates (e.g. an IACA).
        """
        when = at_time or datetime.datetime.now(datetime.timezone.utc)
        if when.tzinfo is None:
            when = when.replace(tzinfo=datetime.timezone.utc)
        if not self.x509_certificates:
            self.load_public_key()
        chain = self.x509_certificates

        for position, cert in enumerate(chain):
            if not _valid_at(cert, when):
                logger.warning(f"Issuer certificate {position} is not valid at {when.isoformat()}")
                return False
            if position + 1 < len(chain) and not _issued_by(cert, chain[position + 1]):
                logger.warning(f"Issuer certificate {position} is not issued by certificate {position + 1}")
                return False

        for anchor in (load_trusted_certificate(c) for c in trusted_certificates or []):
            if not _valid_at(anchor, when):
                continue
            if any(cert == anchor or _issued_by(cert, anchor) for cert in chain):
                return True
        return False

    def verify_signature(self) -> bool:

        if not self.object.key:
            self.load_public_key()

        return self.object.verify_signature()
