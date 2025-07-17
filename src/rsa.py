# WARNING: This is a naive and unsafe RSA implementation for educational purposes only.
# NEVER use it in production cryptographic applications.

import random
import time
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


class RSAModularOperations:
    """
    RSA modular operations using Montgomery arithmetic for efficient modular multiplication.

    Includes a configurable delay in the extra reduction step in the Montgomery multiplication
    in order to increase the timing effect for a side-channel attack demonstration.
    """
    class MontgomeryContext:
        """
        Montgomery arithmetic context for efficient modular operations.

        Montgomery arithmetic represents numbers in a special form that allows
        efficient modular multiplication without expensive division operations.
        """
        def __init__(self, modulus: int, sleep_duration: float = 0.0):
            """
            Initialize Montgomery context for the given modulus.

            Args:
                modulus: The modulus (must be odd for Montgomery arithmetic)
                sleep_duration: Time to sleep on extra reduction (for side-channel demo)

            Raises:
                ValueError: If modulus is even (Montgomery requires odd modulus)
            """
            if modulus % 2 == 0:
                raise ValueError("Montgomery arithmetic requires an odd modulus")

            self.modulus = modulus
            self.sleep_duration = sleep_duration

            # Montgomery parameters
            self.k = modulus.bit_length() # Number of bits in modulus
            self.R = 1 << self.k          # R = 2^k (Montgomery radix)

            # Compute n' such that n * n' ≡ -1 (mod R)
            # We use: n' = R - n^(-1) mod R
            self.n_prime = self.R - pow(self.modulus, -1, self.R)

            # Precompute R² mod n for conversions to Montgomery form
            self.R_squared = (self.R * self.R) % self.modulus

            # Montgomery representation of 1 (used as initial value)
            self.one_mont = self.R % self.modulus

        def _reduce(self, t: int) -> int:
            """
            Montgomery reduction: convert from extended form back to Montgomery form.

            Given t in extended Montgomery form, compute t/R mod n efficiently
            without division by using the Montgomery algorithm.

            Args:
                t: Number in extended Montgomery form

            Returns:
                t/R mod n in Montgomery form
            """
            # Compute m = (t mod R) * n' mod R
            m = ((t & (self.R - 1)) * self.n_prime) & (self.R - 1)

            # Compute u = (t + m*n) / R
            u = (t + m * self.modulus) >> self.k

            # Check if extra reduction is needed
            extra_reduction = u >= self.modulus
            if extra_reduction:
                if self.sleep_duration > 0: # time.sleep(0) waits forever
                    time.sleep(self.sleep_duration)
                u -= self.modulus
            return u

        def to_mont(self, x: int) -> int:
            """
            Convert a regular integer to Montgomery form.

            Args:
                x: Regular integer

            Returns:
                x in Montgomery form (x * R mod n)
            """
            return self._reduce(x * self.R_squared)

        def from_mont(self, x_mont: int) -> int:
            """
            Convert from Montgomery form back to regular integer.

            Args:
                x_mont: Integer in Montgomery form

            Returns:
                Regular integer (x_mont / R mod n)
            """
            return self._reduce(x_mont)

        def multiply(self, a_mont: int, b_mont: int) -> int:
            """
            Multiply two numbers in Montgomery form.

            Args:
                a_mont, b_mont: Numbers in Montgomery form

            Returns:
                Product in Montgomery form
            """
            return self._reduce(a_mont * b_mont)

    @staticmethod
    def exponent(base: int, exp: int, modulus: int, sleep_duration: float = 0.0) -> int:
        """
        Modular exponentiation using the square-and-multiply algorithm and Montgomery arithmetic.

        Args:
            base: Base number
            exp: Exponent
            modulus: Modulus (must be odd)
            sleep_duration: Sleep time for side-channel demonstration

        Returns:
            base^exp mod modulus

        """

        # Handle trivial cases
        if exp == 0:
            return 1
        if exp == 1:
            return base % modulus

        # Initialize Montgomery context
        ctx = RSAModularOperations.MontgomeryContext(modulus, sleep_duration)

        # Convert base to Montgomery form
        base_mont = ctx.to_mont(base)

        # Initialize result to 1 in Montgomery form
        result_mont = ctx.one_mont

        # Square-and-multiply from MSB to LSB with "multiply-then-square" order
        for i in range(exp.bit_length() - 1, -1, -1):
            # 1. Conditional multiplication (if current bit is 1)
            if (exp >> i) & 1:
                result_mont = ctx.multiply(result_mont, base_mont)

            # 2. Squaring (always, except for the last iteration)
            if i > 0:
                result_mont = ctx.multiply(result_mont, result_mont)

        # Convert result back from Montgomery form
        return ctx.from_mont(result_mont)



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

class VulnerableRSA:
    """
    Vulnerable educational RSA implementation with timing side-channel vulnerabilities.

    This implementation demonstrates basic RSA operations without security
    hardening. It includes optional timing delays to simulate side-channel
    attacks during modular exponentiation.
    """
    def __init__(self, public_key: RSAPublicKey, private_key: RSAPrivateKey, sleep_duration: float = 0.0):
        """
        Initialize RSA instance with given key pair.

        Args:
            public_key: RSA public key
            private_key: RSA private key
            sleep_duration: Time delay for side-channel demonstration
        """
        self.public_key = public_key
        self.private_key = private_key
        self.sleep_duration = sleep_duration

    @classmethod
    def generate_keypair(cls, key_length: int, sleep_duration: float = 0.0) -> 'VulnerableRSA':
        """
        Generate a new RSA key pair with the specified bit length.

        Uses the standard RSA key generation algorithm:
        1. Generate two distinct prime numbers p and q
        2. Compute n = p * q and φ(n) = (p-1)(q-1)
        3. Choose public exponent e = 65537
        4. Compute private exponent d = e^(-1) mod φ(n)

        Args:
            key_length: Desired bit length of the RSA modulus
            sleep_duration: Time delay for side-channel demonstration

        Returns:
            VulnerableRSA instance with generated key pair
        """
        e = 65537                         # Standard RSA public exponent (2^16 + 1)
        prime_length = key_length // 2    # Each prime should be half the key length

        # Loop until the generated key pair respect the proper constraints
        while True:
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
            if n.bit_length() == key_length and math.gcd(phi, e) == 1:
                break

        # Compute private exponent d = e^(-1) mod φ(n)
        d = pow(e, -1, phi)

        return cls(
            RSAPublicKey(n=n, e=e),
            RSAPrivateKey(n=n, d=d, p=p, q=q),
            sleep_duration
        )


    def encrypt(self, message: int) -> int:
        """
        Encrypt a message using RSA public key. This is raw RSA without padding.

        Performs raw RSA encryption: ciphertext = message^e mod n

        Args:
            message: Integer message to encrypt (must be < n)

        Returns:
            Encrypted ciphertext as integer
        """
        if message >= self.public_key.n:
            raise ValueError("Message must be smaller than modulus")
        if message < 0:
            raise ValueError("Message must be non-negative")

        return RSAModularOperations.exponent(
            base=message,
            exp=self.public_key.e,
            modulus=self.public_key.n,
            sleep_duration=self.sleep_duration
        )


    def decrypt(self, ciphertext: int) -> int:
        """
        Decrypt a ciphertext using RSA private key.

        Performs raw RSA decryption: message = ciphertext^d mod n

        Args:
            ciphertext: Integer ciphertext to decrypt (must be < n)

        Returns:
            Decrypted message as integer
        """
        if ciphertext >= self.private_key.n:
            raise ValueError("Ciphertext must be smaller than modulus")
        if ciphertext < 0:
            raise ValueError("Ciphertext must be non-negative")

        return RSAModularOperations.exponent(
            base=ciphertext,
            exp=self.private_key.d,
            modulus=self.private_key.n,
            sleep_duration=self.sleep_duration
        )
