# WARNING: This is a naive and unsafe RSA implementation for educational purposes only.
# NEVER use it in production cryptographic applications.

import time
from typing import Tuple

from rsa import TimedRSAInterface, RSAPublicKey, RSAPrivateKey


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
                sleep_duration: Time to sleep on extra reduction (for side-channel attack demo)

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
            sleep_duration: Sleep time for side-channel timing leakage amplification

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





class VulnerableRSA(TimedRSAInterface):
    """
    Vulnerable educational RSA implementation with timing side-channel vulnerabilities.

    This implementation demonstrates basic RSA operations without security
    hardening. It includes optional timing delays to enhance side-channel timing
    leakage during modular exponentiation.

    The algorithm instance is stateless and can work with multiple different key pairs.
    """


    def __init__(self, sleep_duration: float = 0.0):
        """
        Initialize RSA algorithm implementation.

        Args:
            sleep_duration: Time delay for side-channel timing leakage amplification
        """
        self.sleep_duration = sleep_duration


    def timed_encrypt(self, message: int, public_key: RSAPublicKey) -> Tuple[int, float]:
        """
        Encrypt a message using RSA public key. This is raw RSA without padding.

        Performs raw RSA encryption: ciphertext = message^e mod n

        Args:
            message: Integer message to encrypt (must be < n, the RSA modulus)
            public_key: RSA public key to use for encryption

        Returns:
            Tuple of (encrypted_ciphertext, encryption_time)
        """
        if message >= public_key.n:
            raise ValueError("Message must be smaller than modulus")
        if message < 0:
            raise ValueError("Message must be non-negative")

        start_time = time.perf_counter()
        ciphertext = RSAModularOperations.exponent(
            base=message,
            exp=public_key.e,
            modulus=public_key.n,
            sleep_duration=self.sleep_duration
        )
        timing = time.perf_counter() - start_time

        return ciphertext, timing

    def timed_decrypt(self, ciphertext: int, private_key: RSAPrivateKey) -> Tuple[int, float]:
        """
        Decrypt a ciphertext using RSA private key.

        Performs raw RSA decryption: message = ciphertext^d mod n

        Args:
            ciphertext: Integer ciphertext to decrypt (must be < n, the RSA modulus)
            private_key: RSA private key to use for decryption

        Returns:
            Tuple of (decrypted_message, decryption_time)
        """
        if ciphertext >= private_key.n:
            raise ValueError("Ciphertext must be smaller than modulus")
        if ciphertext < 0:
            raise ValueError("Ciphertext must be non-negative")

        start_time = time.perf_counter()
        plaintext = RSAModularOperations.exponent(
            base=ciphertext,
            exp=private_key.d,
            modulus=private_key.n,
            sleep_duration=self.sleep_duration
        )
        timing = time.perf_counter() - start_time

        return plaintext, timing

    def timed_sign(self, message: int, private_key: RSAPrivateKey) -> Tuple[int, float]:
        """
        Sign a message using RSA private key signing.

        Performs raw RSA signing: signature = message^d mod n
        Note: This is mathematically equivalent to decryption.

        Args:
            message: Integer message to sign (must be < n, the RSA modulus)
            private_key: RSA private key to use for signing

        Returns:
            Tuple of (signature, signing_time)
        """
        if message >= private_key.n:
            raise ValueError("Message must be smaller than modulus")
        if message < 0:
            raise ValueError("Message must be non-negative")

        start_time = time.perf_counter()
        signature = RSAModularOperations.exponent(
            base=message,
            exp=private_key.d,
            modulus=private_key.n,
            sleep_duration=self.sleep_duration
        )
        timing = time.perf_counter() - start_time

        return signature, timing

    def timed_verify(self, signature: int, message: int, public_key: RSAPublicKey) -> Tuple[bool, float]:
        """
        Verify a signature against a message using RSA public key verification.

        Performs raw RSA verification: recovered_message = signature^e mod n
        Then compares recovered_message with the original message.

        Args:
            signature: The signature to verify
            message: The original message
            public_key: RSA public key to use for verification

        Returns:
            Tuple of (is_signature_valid, verification_time)
        """
        if signature >= public_key.n:
            raise ValueError("Signature must be smaller than modulus")

        if signature < 0:
            raise ValueError("Signature must be non-negative")

        if message >= public_key.n:
            raise ValueError("Message must be smaller than modulus")

        if message < 0:
            raise ValueError("Message must be non-negative")

        start_time = time.perf_counter()
        recovered_message = RSAModularOperations.exponent(
            base=signature,
            exp=public_key.e,
            modulus=public_key.n,
            sleep_duration=self.sleep_duration
        )
        timing = time.perf_counter() - start_time

        is_valid = (recovered_message == message)
        return is_valid, timing
