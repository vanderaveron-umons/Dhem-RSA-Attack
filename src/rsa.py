import base64
import re

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Tuple

from pyasn1.codec.der import decoder, encoder
from pyasn1.error import PyAsn1Error
from pyasn1.type import univ, namedtype


class TimedRSAInterface(ABC):
    """
    Abstract base class defining the standard interface for RSA algorithm implementations.

    This interface separates the RSA algorithm implementation from specific key pairs,
    allowing a single algorithm instance to work with multiple different keys.
    All operations return both the result and the time taken to perform the operation.
    """

    @abstractmethod
    def timed_encrypt(self, message: int, public_key: 'RSAPublicKey') -> Tuple[int, float]:
        """
        Encrypts the given message using RSA public key encryption.

        Args:
            message: The message to encrypt (must be < n, the RSA modulus)
            public_key: RSA public key to use for encryption

        Returns:
            Tuple of (encrypted_ciphertext, encryption_time)
        """
        pass

    @abstractmethod
    def timed_decrypt(self, ciphertext: int, private_key: 'RSAPrivateKey') -> Tuple[int, float]:
        """
        Decrypts the given ciphertext using RSA private key decryption.

        Args:
            ciphertext: The ciphertext to decrypt (must be < n, the RSA modulus)
            private_key: RSA private key to use for decryption

        Returns:
            Tuple of (decrypted_message, decryption_time)
        """
        pass

    @abstractmethod
    def timed_sign(self, message: int, private_key: 'RSAPrivateKey') -> Tuple[int, float]:
        """
        Signs the given message using RSA private key signing.

        Note: This is raw RSA signing without padding or hashing.

        Args:
            message: The message to sign (must be < n, the RSA modulus)
            private_key: RSA private key to use for signing

        Returns:
            Tuple of (signature, signing_time)
        """
        pass

    @abstractmethod
    def timed_verify(self, signature: int, message: int, public_key: 'RSAPublicKey') -> Tuple[bool, float]:
        """
        Verifies the given signature against the message using RSA public key verification.

        Note: This is raw RSA verification without padding or hashing.

        Args:
            signature: The signature to verify
            message: The original message
            public_key: RSA public key to use for verification

        Returns:
            Tuple of (is_valid, verification_time)
        """
        pass


# ========================== #
# RSA structures and helpers #
# ========================== #
@dataclass
class RSAPublicKey:
    """
    RSA public key containing the modulus and public exponent.

    Attributes:
        n: The RSA modulus (product of two primes)
        e: The public exponent (typically 65537)
    """
    n: int
    e: int


@dataclass
class RSAPrivateKey:
    """
    RSA private key containing the modulus and private exponent.

    Attributes:
        n: The RSA modulus (same as in public key)
        d: The private exponent (multiplicative inverse of e mod φ(n))
        p: First prime factor
        q: Second prime factor
    """
    n: int
    d: int
    p: int
    q: int


@dataclass
class RSAKeyPair:
    """
    RSA key pair containing both public and private keys.

    Attributes:
        public_key: RSA public key
        private_key: RSA private key
    """
    public_key: RSAPublicKey
    private_key: RSAPrivateKey

    @classmethod
    def from_components(cls, p: int, q: int, e: int, d: int) -> 'RSAKeyPair':
        """
        Creates a new RSAKeyPair from the given components (p, q, e, d).
        WARNING: no validity check is performed.

        Args:
            p: First prime factor
            q: Second prime factor
            e: The public exponent
            d: The private exponent

        Returns:
            A new instance of RSAKeyPair.

        """
        n = p * q

        public_key = RSAPublicKey(n=n, e=e)
        private_key = RSAPrivateKey(n=n, d=d, p=p, q=q)

        return cls(public_key=public_key, private_key=private_key)

    @classmethod
    def from_pem_private(cls, pem_data: str) -> 'RSAKeyPair':
        """
        Import PKCS#1 PEM private key and return an RSAKeyPair instance.
        The private key PEM contains all necessary public key components.
        """
        der_data = _pem_to_der(pem_data, "RSA PRIVATE KEY")
        try:
            private_key_asn1, _ = decoder.decode(der_data, asn1Spec=_RSAPrivateKeyASN1())
        except PyAsn1Error as e:
            raise ValueError(f"Invalid ASN.1 structure for private key: {e}")

        n = int(private_key_asn1.getComponentByName('modulus'))
        e = int(private_key_asn1.getComponentByName('publicExponent'))
        d = int(private_key_asn1.getComponentByName('privateExponent'))
        p = int(private_key_asn1.getComponentByName('prime1'))
        q = int(private_key_asn1.getComponentByName('prime2'))

        public_key = RSAPublicKey(n=n, e=e)
        private_key = RSAPrivateKey(n=n, d=d, p=p, q=q)

        return cls(public_key=public_key, private_key=private_key)

    def export_private_pem(self) -> str:
        """Export RSA key pair as a PKCS#1 PEM private key string."""
        # Calculate CRT parameters needed for the standard format
        exp1 = self.private_key.d % (self.private_key.p - 1)  # dP
        exp2 = self.private_key.d % (self.private_key.q - 1)  # dQ
        coeff = pow(self.private_key.q, -1, self.private_key.p)  # qInv

        # Build the ASN.1 structure
        private_key_asn1 = _RSAPrivateKeyASN1()
        private_key_asn1.setComponentByName('version', 0)
        private_key_asn1.setComponentByName('modulus', self.private_key.n)
        private_key_asn1.setComponentByName('publicExponent', self.public_key.e)
        private_key_asn1.setComponentByName('privateExponent', self.private_key.d)
        private_key_asn1.setComponentByName('prime1', self.private_key.p)
        private_key_asn1.setComponentByName('prime2', self.private_key.q)
        private_key_asn1.setComponentByName('exponent1', exp1)
        private_key_asn1.setComponentByName('exponent2', exp2)
        private_key_asn1.setComponentByName('coefficient', coeff)

        der_data = encoder.encode(private_key_asn1)
        return _der_to_pem(der_data, "RSA PRIVATE KEY")

    def export_public_pem(self) -> str:
        """Export the public part of the key pair as a PKCS#1 PEM public key string."""
        public_key_asn1 = _RSAPublicKeyASN1()
        public_key_asn1.setComponentByName('modulus', self.public_key.n)
        public_key_asn1.setComponentByName('publicExponent', self.public_key.e)

        der_data = encoder.encode(public_key_asn1)
        return _der_to_pem(der_data, "RSA PUBLIC KEY")


# ==================================== #
# ASN.1 structures and PEM/DER helpers #
# ==================================== #
class _RSAPrivateKeyASN1(univ.Sequence):
    """
    PKCS#1 RSAPrivateKey ASN.1 structure (RFC 3447).
    This structure contains not only the private key but also the public key
    components and parameters for CRT (Chinese Remainder Theorem) optimization.
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', univ.Integer()),              # Must be 0 for two-prime RSA
        namedtype.NamedType('modulus', univ.Integer()),              # n (public)
        namedtype.NamedType('publicExponent', univ.Integer()),       # e (public)
        namedtype.NamedType('privateExponent', univ.Integer()),      # d (private)
        namedtype.NamedType('prime1', univ.Integer()),               # p (private)
        namedtype.NamedType('prime2', univ.Integer()),               # q (private)
        # --- CRT components for faster private key operations ---
        namedtype.NamedType('exponent1', univ.Integer()),            # d mod (p-1)
        namedtype.NamedType('exponent2', univ.Integer()),            # d mod (q-1)
        namedtype.NamedType('coefficient', univ.Integer()),          # (inverse of q) mod p
    )


class _RSAPublicKeyASN1(univ.Sequence):
    """PKCS#1 RSAPublicKey ASN.1 structure (RFC 3447)."""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('modulus', univ.Integer()),              # n
        namedtype.NamedType('publicExponent', univ.Integer()),       # e
    )


def _der_to_pem(der_data: bytes, key_type: str) -> str:
    """Convert DER (binary) data to PEM (Base64 text) format."""
    b64_data = base64.b64encode(der_data).decode('ascii')
    # Split into 64-character lines as per PEM standard
    lines = [b64_data[i:i + 64] for i in range(0, len(b64_data), 64)]
    header = f"-----BEGIN {key_type}-----"
    footer = f"-----END {key_type}-----"
    return '\n'.join([header] + lines + [footer])


def _pem_to_der(pem_data: str, expected_type: str) -> bytes:
    """Convert PEM format to DER binary data, with validation."""
    pem_data = pem_data.strip()
    header = f"-----BEGIN {expected_type}-----"
    footer = f"-----END {expected_type}-----"

    if not (pem_data.startswith(header) and pem_data.endswith(footer)):
        raise ValueError(f"PEM data does not have valid headers/footers for {expected_type}")

    # Extract the Base64 content between the headers
    b64_block = pem_data[len(header):-len(footer)].strip()

    # Delete all spaces, including newline.
    b64_content = re.sub(r'\s+', '', b64_block)

    try:
        # Decode the Base64 content. The 'validate=True' flag ensures that the
        # input contains only valid Base64 characters.
        return base64.b64decode(b64_content, validate=True)
    except (ValueError, TypeError) as e:
        raise ValueError(f"Invalid Base64 encoding in PEM data: {e}")

