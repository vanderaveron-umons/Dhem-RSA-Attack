import random
import math
import argparse
import sys

from src.rsa import RSAKeyPair

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

        e = public_exponent
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
            if n.bit_length() == key_length and math.gcd(phi, e) == 1:
                # Compute private exponent d = e^(-1) mod φ(n)
                d = pow(public_exponent, -1, phi)

                return RSAKeyPair.from_components(p, q, e, d)
        raise RuntimeError(f"Unable to generate suitable RSA key pair after {max_attempts} attempts")

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
