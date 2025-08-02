import unittest
import subprocess
import shutil
import random
from typing import List, Callable

# Import RSA implementations to test
from rsa import TimedRSAInterface
from rsa_vulnerable import VulnerableRSA
from rsa_key_generator import RSAKeyGenerator

# Import the necessary components from the 'cryptography' library
from cryptography.hazmat.primitives.asymmetric import rsa



def get_rsa_implementations() -> List[Callable[[], TimedRSAInterface]]:
    """
    Factory function returning all RSA implementations to test.

    Returns:
        List of factory functions that create RSA implementation instances
    """
    return [
        lambda: VulnerableRSA(sleep_duration=0.0),  # Fast version for testing
        lambda: VulnerableRSA(sleep_duration=0.00001),  # With timing side-channel
        # Add more implementations here as you develop them:
        # lambda: SecureRSA(),
        # lambda: OptimizedRSA(),
    ]


def is_openssl_available():
    """Check if the 'openssl' command is available in the system's PATH."""
    return shutil.which("openssl") is not None


class TestRSAImplementations(unittest.TestCase):
    """
    Comprehensive test suite for RSA implementations.
    Tests all implementations against known values, edge cases, and interoperability.
    """

    def setUp(self):
        """Set up test fixtures before each test method."""
        # Generate test key pairs of different sizes for testing
        self.test_keys = {
            256: RSAKeyGenerator.generate_keypair(256, seed=42),
            512: RSAKeyGenerator.generate_keypair(512, seed=43),
            1024: RSAKeyGenerator.generate_keypair(1024, seed=44),
        }

        # Fixed test vectors for consistency
        self.test_messages = [1, 2, 3, 42, 123, 999, 12345]

        # Random seed for reproducible random tests
        random.seed(12345)

    def test_basic_encrypt_decrypt_cycle(self):
        """Test basic encrypt/decrypt cycle for all implementations."""
        print("\n--- Testing basic encrypt/decrypt cycle ---")

        for impl_factory in get_rsa_implementations():
            with self.subTest(implementation=impl_factory().__class__.__name__):
                rsa_impl = impl_factory()

                for key_size, key_pair in self.test_keys.items():
                    with self.subTest(key_size=key_size):
                        for message in self.test_messages:
                            if message < key_pair.public_key.n:  # Ensure message < modulus
                                # Encrypt then decrypt
                                ciphertext, enc_time = rsa_impl.timed_encrypt(message, key_pair.public_key)
                                decrypted, dec_time = rsa_impl.timed_decrypt(ciphertext, key_pair.private_key)

                                self.assertEqual(message, decrypted,
                                                 f"Encrypt/decrypt failed for message {message} with {key_size}-bit key")
                                self.assertGreater(enc_time, 0, "Encryption time should be positive")
                                self.assertGreater(dec_time, 0, "Decryption time should be positive")

    def test_basic_sign_verify_cycle(self):
        """Test basic sign/verify cycle for all implementations."""
        print("\n--- Testing basic sign/verify cycle ---")

        for impl_factory in get_rsa_implementations():
            with self.subTest(implementation=impl_factory().__class__.__name__):
                rsa_impl = impl_factory()

                for key_size, key_pair in self.test_keys.items():
                    with self.subTest(key_size=key_size):
                        for message in self.test_messages:
                            if message < key_pair.public_key.n:  # Ensure message < modulus
                                # Sign then verify
                                signature, sign_time = rsa_impl.timed_sign(message, key_pair.private_key)
                                is_valid, verify_time = rsa_impl.timed_verify(signature, message, key_pair.public_key)

                                self.assertTrue(is_valid,
                                                f"Sign/verify failed for message {message} with {key_size}-bit key")
                                self.assertGreater(sign_time, 0, "Signing time should be positive")
                                self.assertGreater(verify_time, 0, "Verification time should be positive")

    def test_random_messages(self):
        """Test with random messages to catch edge cases."""
        print("\n--- Testing with random messages ---")

        for impl_factory in get_rsa_implementations():
            with self.subTest(implementation=impl_factory().__class__.__name__):
                rsa_impl = impl_factory()

                for key_size, key_pair in self.test_keys.items():
                    with self.subTest(key_size=key_size):
                        # Test with 10 random messages
                        for _ in range(10):
                            message = random.randrange(1, key_pair.public_key.n)

                            # Test encrypt/decrypt
                            ciphertext, _ = rsa_impl.timed_encrypt(message, key_pair.public_key)
                            decrypted, _ = rsa_impl.timed_decrypt(ciphertext, key_pair.private_key)
                            self.assertEqual(message, decrypted)

                            # Test sign/verify
                            signature, _ = rsa_impl.timed_sign(message, key_pair.private_key)
                            is_valid, _ = rsa_impl.timed_verify(signature, message, key_pair.public_key)
                            self.assertTrue(is_valid)

    def test_edge_cases(self):
        """Test edge cases and error conditions."""
        print("\n--- Testing edge cases ---")

        for impl_factory in get_rsa_implementations():
            with self.subTest(implementation=impl_factory().__class__.__name__):
                rsa_impl = impl_factory()
                key_pair = self.test_keys[512]  # Use 512-bit key for edge tests

                # Test message = 1 (smallest valid message)
                ciphertext, _ = rsa_impl.timed_encrypt(1, key_pair.public_key)
                decrypted, _ = rsa_impl.timed_decrypt(ciphertext, key_pair.private_key)
                self.assertEqual(1, decrypted)

                # Test message = n-1 (largest valid message)
                max_message = key_pair.public_key.n - 1
                ciphertext, _ = rsa_impl.timed_encrypt(max_message, key_pair.public_key)
                decrypted, _ = rsa_impl.timed_decrypt(ciphertext, key_pair.private_key)
                self.assertEqual(max_message, decrypted)

                # Test invalid messages (should raise ValueError)
                with self.assertRaises(ValueError):
                    rsa_impl.timed_encrypt(-1, key_pair.public_key)  # Negative message

                with self.assertRaises(ValueError):
                    rsa_impl.timed_encrypt(key_pair.public_key.n, key_pair.public_key)  # Message >= n

                with self.assertRaises(ValueError):
                    rsa_impl.timed_decrypt(-1, key_pair.private_key)  # Negative ciphertext

    def test_consistency_between_implementations(self):
        """Test that all implementations produce the same results."""
        print("\n--- Testing consistency between implementations ---")

        implementations = [factory() for factory in get_rsa_implementations()]
        if len(implementations) < 2:
            self.skipTest("Need at least 2 implementations to test consistency")

        key_pair = self.test_keys[512]
        test_message = 12345

        # Get results from first implementation as reference
        reference_impl = implementations[0]
        ref_ciphertext, _ = reference_impl.timed_encrypt(test_message, key_pair.public_key)
        ref_signature, _ = reference_impl.timed_sign(test_message, key_pair.private_key)

        # Test that all other implementations produce the same results
        for impl in implementations[1:]:
            with self.subTest(implementation=impl.__class__.__name__):
                # Test encryption consistency
                ciphertext, _ = impl.timed_encrypt(test_message, key_pair.public_key)
                self.assertEqual(ref_ciphertext, ciphertext,
                                 "Encryption results should be consistent across implementations")

                # Test signing consistency
                signature, _ = impl.timed_sign(test_message, key_pair.private_key)
                self.assertEqual(ref_signature, signature,
                                 "Signing results should be consistent across implementations")

                # Test cross-verification (decrypt with different impl)
                decrypted, _ = impl.timed_decrypt(ref_ciphertext, key_pair.private_key)
                self.assertEqual(test_message, decrypted)

                # Test cross-verification (verify with different impl)
                is_valid, _ = impl.timed_verify(ref_signature, test_message, key_pair.public_key)
                self.assertTrue(is_valid)

    def test_interop_with_cryptography_library(self):
        """Test interoperability with Python's cryptography library."""
        print("\n--- Testing interoperability with cryptography library ---")

        for impl_factory in get_rsa_implementations():
            with self.subTest(implementation=impl_factory().__class__.__name__):
                rsa_impl = impl_factory()
                our_key_pair = self.test_keys[1024]  # Use 1024-bit key for crypto lib compatibility

                # Convert our key to cryptography format
                crypto_private_key = rsa.RSAPrivateNumbers(
                    p=our_key_pair.private_key.p,
                    q=our_key_pair.private_key.q,
                    d=our_key_pair.private_key.d,
                    dmp1=our_key_pair.private_key.d % (our_key_pair.private_key.p - 1),
                    dmq1=our_key_pair.private_key.d % (our_key_pair.private_key.q - 1),
                    iqmp=pow(our_key_pair.private_key.q, -1, our_key_pair.private_key.p),
                    public_numbers=rsa.RSAPublicNumbers(
                        e=our_key_pair.public_key.e,
                        n=our_key_pair.public_key.n
                    )
                ).private_key()

                test_message = 123456

                # Test: Our encrypt, crypto decrypt
                our_ciphertext, _ = rsa_impl.timed_encrypt(test_message, our_key_pair.public_key)
                crypto_decrypted = pow(our_ciphertext, our_key_pair.private_key.d, our_key_pair.public_key.n)
                self.assertEqual(test_message, crypto_decrypted,
                                 "Cryptography library should be able to decrypt our ciphertext")

                # Test: Crypto encrypt, our decrypt
                crypto_ciphertext = pow(test_message, our_key_pair.public_key.e, our_key_pair.public_key.n)
                our_decrypted, _ = rsa_impl.timed_decrypt(crypto_ciphertext, our_key_pair.private_key)
                self.assertEqual(test_message, our_decrypted,
                                 "We should be able to decrypt cryptography library ciphertext")

    @unittest.skipIf(not is_openssl_available(), "openssl command not found")
    def test_interop_with_openssl(self):
        """Test interoperability with OpenSSL command line tool."""
        print("\n--- Testing interoperability with OpenSSL ---")

        for impl_factory in get_rsa_implementations():
            with self.subTest(implementation=impl_factory().__class__.__name__):
                rsa_impl = impl_factory()
                our_key_pair = self.test_keys[1024]  # Use 1024-bit key

                # Export our key to PEM format
                private_pem = our_key_pair.export_private_pem()

                # Test that OpenSSL can parse our key
                process = subprocess.run(
                    ["openssl", "rsa", "-text", "-noout"],
                    input=private_pem.encode('utf-8'),
                    capture_output=True,
                    check=False
                )

                self.assertEqual(process.returncode, 0,
                                 f"OpenSSL should be able to parse our key. Error: {process.stderr.decode()}")

                # The output should contain our modulus and exponents
                output = process.stdout.decode()
                self.assertIn("modulus", output.lower())
                self.assertIn("publicExponent", output)

    def test_timing_behavior(self):
        """Test timing behavior of implementations (mainly for VulnerableRSA)."""
        print("\n--- Testing timing behavior ---")

        # Test specifically implementations with different sleep durations
        fast_impl = VulnerableRSA(sleep_duration=0.0)
        slow_impl = VulnerableRSA(sleep_duration=0.001)  # 1ms delay

        key_pair = self.test_keys[256]  # Use smaller key for faster testing
        test_message = 12345

        # Measure timing for fast implementation
        fast_times = []
        for _ in range(5):
            _, dec_time = fast_impl.timed_decrypt(
                fast_impl.timed_encrypt(test_message, key_pair.public_key)[0],
                key_pair.private_key
            )
            fast_times.append(dec_time)

        # Measure timing for slow implementation
        slow_times = []
        for _ in range(5):
            _, dec_time = slow_impl.timed_decrypt(
                slow_impl.timed_encrypt(test_message, key_pair.public_key)[0],
                key_pair.private_key
            )
            slow_times.append(dec_time)

        avg_fast = sum(fast_times) / len(fast_times)
        avg_slow = sum(slow_times) / len(slow_times)

        print(f"    Fast implementation avg time: {avg_fast:.6f}s")
        print(f"    Slow implementation avg time: {avg_slow:.6f}s")

        # Slow implementation should be noticeably slower
        self.assertGreater(avg_slow, avg_fast * 2,
                           "Slow implementation should be significantly slower than fast one")

    def test_mathematical_properties(self):
        """Test mathematical properties of RSA."""
        print("\n--- Testing mathematical properties ---")

        for impl_factory in get_rsa_implementations():
            with self.subTest(implementation=impl_factory().__class__.__name__):
                rsa_impl = impl_factory()
                key_pair = self.test_keys[512]

                # Test RSA property: (m^e)^d ≡ m (mod n)
                test_message = 54321
                ciphertext, _ = rsa_impl.timed_encrypt(test_message, key_pair.public_key)
                decrypted, _ = rsa_impl.timed_decrypt(ciphertext, key_pair.private_key)
                self.assertEqual(test_message, decrypted)

                # Test signing property: signature^e ≡ message (mod n)
                signature, _ = rsa_impl.timed_sign(test_message, key_pair.private_key)
                recovered = pow(signature, key_pair.public_key.e, key_pair.public_key.n)
                self.assertEqual(test_message, recovered)

                # Test encrypt(m1) * encrypt(m2) ≡ encrypt(m1 * m2) (mod n)
                # This is the multiplicative property of RSA
                m1, m2 = 123, 456
                if (m1 * m2) < key_pair.public_key.n:  # Ensure product is valid
                    c1, _ = rsa_impl.timed_encrypt(m1, key_pair.public_key)
                    c2, _ = rsa_impl.timed_encrypt(m2, key_pair.public_key)
                    c_product, _ = rsa_impl.timed_encrypt((m1 * m2) % key_pair.public_key.n, key_pair.public_key)

                    combined = (c1 * c2) % key_pair.public_key.n
                    self.assertEqual(c_product, combined,
                                     "RSA should preserve multiplicative structure")


def run_specific_implementation_tests(impl_name: str):
    """
    Run tests for a specific implementation only.

    Args:
        impl_name: Name of the implementation class to test
    """
    # Filter implementations to test only the specified one
    original_function = get_rsa_implementations

    def filtered_implementations():
        all_impls = original_function()
        return [impl for impl in all_impls if impl().__class__.__name__ == impl_name]

    # Temporarily replace the function
    globals()['get_rsa_implementations'] = filtered_implementations

    try:
        unittest.main(verbosity=2)
    finally:
        # Restore original function
        globals()['get_rsa_implementations'] = original_function


if __name__ == '__main__':
    print("RSA Implementation Test Suite")
    print("=" * 50)

    # List available implementations
    implementations = get_rsa_implementations()
    print(f"Testing {len(implementations)} RSA implementations:")
    for impl_factory in implementations:
        impl = impl_factory()
        print(f"  - {impl.__class__.__name__}")

    print(f"OpenSSL available: {is_openssl_available()}")
    print("=" * 50)

    # Run all tests
    unittest.main(verbosity=2, exit=False)

    print("\n" + "=" * 50)
    print("✅ RSA implementation tests completed!")
    print("💡 To test a specific implementation, use:")
    print("   python test_rsa.py <ImplementationName>")