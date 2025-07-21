import random
import math
from dataclasses import dataclass

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


class RSAKeyGenerator:
    """
    RSA key pair generator that creates RSA keys using secure prime generation.
    
    This class extracts the key generation logic to be reusable across different
    RSA implementations while maintaining the same security properties.
    """
    
    @staticmethod
    def generate_keypair(key_length: int, public_exponent: int = 65537) -> RSAKeyPair:
        """
        Generate a new RSA key pair with the specified bit length.

        Uses the standard RSA key generation algorithm:
        1. Generate two distinct prime numbers p and q
        2. Compute n = p * q and φ(n) = (p-1)(q-1)
        3. Choose public exponent e (default 65537)
        4. Compute private exponent d = e^(-1) mod φ(n)

        Args:
            key_length: Desired bit length of the RSA modulus
            public_exponent: Public exponent (default 65537)

        Returns:
            RSAKeyPair containing public and private keys

        Raises:
            ValueError: If key_length is too small or public_exponent is invalid
            RuntimeError: If unable to generate suitable primes
        """
        if key_length < 64:
            raise ValueError("Key length must be at least 64 bits")
        
        if public_exponent < 3 or public_exponent % 2 == 0:
            raise ValueError("Public exponent must be odd and >= 3")
            
        prime_length = key_length // 2    # Each prime should be half the key length

        # Loop until the generated key pair respects the proper constraints
        max_attempts = 1000
        for attempt in range(max_attempts):
            # Generate two prime numbers of equal bit length
            p = PrimeGenerator.generate_prime(prime_length)
            q = PrimeGenerator.generate_prime(prime_length)

            # Ensure primes are distinct
            if p == q:
                continue
                
            # Compute RSA parameters
            n = p * q
            phi = (p - 1) * (q - 1)  # Euler's totient function

            # Verify constraints:
            # 1. Modulus has exactly the desired bit length
            # 2. e and φ(n) are coprime (required for d to exist)
            if n.bit_length() == key_length and math.gcd(phi, public_exponent) == 1:
                # Compute private exponent d = e^(-1) mod φ(n)
                d = pow(public_exponent, -1, phi)
                
                public_key = RSAPublicKey(n=n, e=public_exponent)
                private_key = RSAPrivateKey(n=n, d=d, p=p, q=q)
                
                return RSAKeyPair(
                    public_key=public_key,
                    private_key=private_key
                )
        
        raise RuntimeError(f"Unable to generate suitable RSA key pair after {max_attempts} attempts")