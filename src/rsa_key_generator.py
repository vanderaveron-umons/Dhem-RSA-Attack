import base64
import random
import math
import re
from dataclasses import dataclass

import argparse
import sys

from pyasn1.type import univ, namedtype
from pyasn1.codec.der import encoder, decoder
from pyasn1.error import PyAsn1Error


# ========================================== #
# Helpers classes to generate random numbers #
# ========================================== #
class PrimeGenerator:
    """
    A simple prime number generator using Miller-Rabin primality test for probabilistic prime checking.
    """
    @staticmethod
    def _is_prime(n: int, iterations: int = 10) -> bool:
        """
        Miller-Rabin probabilistic primality test.

        Args:
            n: The number to test for primality
            iterations: Number of iterations to perform (higher = more accurate)

        Returns:
            True if n is probably prime, False if n is definitely composite
        """

        # Handle trivial cases
        if n < 2: return False
        if n in (2, 3): return True
        if n % 2 == 0: return False

        # Write n-1 as d * 2^r where d is odd
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2

        # Perform Miller-Rabin test iterations
        for _ in range(iterations):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue

            # Square x repeatedly r-1 times
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1: break
            else:
                # If we never found x == n-1, n is composite
                return False
        return True

    @staticmethod
    def generate_prime(bits: int, max_attempts: int = 10000) -> int:
        """
        Generate a random prime number with exactly the specified bit length.

        Args:
            bits: The desired bit length of the prime
            max_attempts: Maximum number of candidates to try

        Returns:
            A prime number with exactly 'bits' bits

        Raises:
            RuntimeError: If no prime found within max_attempts
        """

        for _ in range(max_attempts):
            # Generate random number with exact bit length
            # Set MSB to 1 (ensures exact bit length) and LSB to 1 (ensures odd)
            p = random.getrandbits(bits) | (1 << bits - 1) | 1
            if PrimeGenerator._is_prime(p):
                return p
        raise RuntimeError(f"Unable to generate a {bits} bits prime after {max_attempts} attempts.")


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


class RSAKeyGenerator:
    """
    Generate a new RSA key pair with the specified bit length.

    Args:
            key_length: Desired bit length of the RSA modulus

    Returns:
        RSAKeyPair containing public and private keys

    Raises:
        ValueError: If key_length is too small or public_exponent is invalid
        RuntimeError: If unable to generate suitable primes

    """

    @staticmethod
    def generate_keypair(key_length: int, public_exponent: int = 65537) -> RSAKeyPair:
        if public_exponent < 3 or public_exponent % 2 == 0:
            raise ValueError("Public exponent must be odd and >= 3")

        prime_length = key_length // 2
        max_attempts = 1000
        # Loop until the generated key pair respect the proper constraints or the
        # max attempts limit is reached
        for _ in range(max_attempts):
            # Generate two prime numbers of equal bit length
            p = PrimeGenerator.generate_prime(prime_length)
            q = PrimeGenerator.generate_prime(prime_length)

            # Ensure primes are distinct
            if p == q:
                continue

            # Compute RSA parameters
            n = p * q
            phi = (p - 1) * (q - 1)

            # Verify constraints:
            # 1. Modulus has exactly the desired bit length
            # 2. e and φ(n) are coprime (required for d to exist)
            if n.bit_length() == key_length and math.gcd(phi, public_exponent) == 1:
                # Compute private exponent d = e^(-1) mod φ(n)
                d = pow(public_exponent, -1, phi)

                public_key = RSAPublicKey(n=n, e=public_exponent)
                private_key = RSAPrivateKey(n=n, d=d, p=p, q=q)
                return RSAKeyPair(public_key=public_key, private_key=private_key)
        raise RuntimeError(f"Unable to generate suitable RSA key pair after {max_attempts} attempts")


if __name__ == '__main__':
    # Create a top-level parser for the command-line interface
    parser = argparse.ArgumentParser(
        description="A simple tool to generate and inspect RSA key pairs.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    # Create subparsers for different commands (generate, read)
    subparsers = parser.add_subparsers(dest='command', required=True, help='Available commands')

    # --- 'generate' command ---
    parser_gen = subparsers.add_parser(
        'generate',
        help='Generate a new RSA key pair and save it to a PEM file.'
    )
    parser_gen.add_argument(
        '-b', '--bits',
        type=int,
        default=2048,
        help='The desired bit length of the RSA key (default: 2048).'
    )
    parser_gen.add_argument(
        '-o', '--out',
        type=str,
        required=True,
        help='Path to the output file to save the private key (PEM format).'
    )

    # --- 'read' command ---
    parser_read = subparsers.add_parser(
        'read',
        help='Read a private key from a PEM file and display its components.'
    )
    parser_read.add_argument(
        '-f', '--file',
        type=str,
        required=True,
        help='Path to the input private key file (PEM format).'
    )

    # Parse the command-line arguments provided by the user
    args = parser.parse_args()

    # --- Command Execution Logic ---
    if args.command == 'generate':
        try:
            # Generate the key pair
            print(f"Generating a {args.bits}-bit RSA key pair... ", end='', flush=True)
            keypair = RSAKeyGenerator.generate_keypair(key_length=args.bits)
            print("Done.")

            # Export the full private key to PEM format
            private_pem = keypair.export_private_pem()

            # Write the PEM data to the specified output file
            with open(args.out, 'w') as f:
                f.write(private_pem)
            print(f"✅ Private key successfully saved to '{args.out}'")

        except (ValueError, RuntimeError) as e:
            print(f"\nError: {e}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"\nAn unexpected error occurred: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.command == 'read':
        try:
            # Read the PEM file content
            with open(args.file, 'r') as f:
                pem_data = f.read()

            # Import the key pair from the PEM data
            keypair = RSAKeyPair.from_pem_private(pem_data)
            pub = keypair.public_key
            priv = keypair.private_key

            # Display all the key components in a readable format
            print("--- RSA Private Key Components ---")
            print(f"Modulus (n):          {priv.n}")
            print(f"Public Exponent (e):  {pub.e}")
            print(f"Private Exponent (d): {priv.d}")
            print(f"Prime 1 (p):          {priv.p}")
            print(f"Prime 2 (q):          {priv.q}")

        except FileNotFoundError:
            print(f"Error: The file '{args.file}' was not found.", file=sys.stderr)
            sys.exit(1)
        except ValueError as e:
            # This handles various errors: bad PEM format, public key only, etc.
            print(f"Error reading PEM file: {e}", file=sys.stderr)
            print("Please ensure the file is a valid PKCS#1 private key in PEM format.", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"An unexpected error occurred: {e}", file=sys.stderr)
            sys.exit(1)
