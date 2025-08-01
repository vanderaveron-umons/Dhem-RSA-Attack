import time
import random
import numpy as np
from typing import List, Optional
from dataclasses import dataclass

# Import the vulnerable RSA implementation and key generation
from rsa_vulnerable import VulnerableRSA
from rsa_key_generator import RSAKeyGenerator
from rsa import RSAPublicKey, RSAPrivateKey


@dataclass
class TimingSample:
    """
    Represents a single timing measurement for a ciphertext decryption.
    """
    ciphertext: int
    timing: float


class AttackEnvironment:
    """
    Prepares the complete environment for a Dhem timing attack.
    This class generates the RSA key pair and collects the timing samples.
    """

    def __init__(self, key_length: int, sleep_duration: float, num_traces: int):
        self.key_length = key_length
        self.sleep_duration = sleep_duration
        self.num_traces = num_traces

        # Generate RSA key pair using the new key generator
        key_pair = RSAKeyGenerator.generate_keypair(key_length)
        self.rsa_instance = VulnerableRSA(
            public_key=key_pair.public_key,
            private_key=key_pair.private_key,
            sleep_duration=sleep_duration
        )
        self.timing_samples: List[TimingSample] = self._collect_timing_samples()

    def _collect_timing_samples(self) -> List[TimingSample]:
        """
        Collects timing samples by encrypting random messages and measuring decryption time.
        """
        timing_samples = []
        for _ in range(self.num_traces):
            message = random.randrange(1, self.rsa_instance.public_key.n)
            ciphertext = self.rsa_instance.encrypt(message)

            start_time = time.perf_counter()
            self.rsa_instance.decrypt(ciphertext)
            timing = time.perf_counter() - start_time

            timing_samples.append(TimingSample(ciphertext, timing))
        return timing_samples

    def get_public_key(self) -> RSAPublicKey:
        return self.rsa_instance.public_key

    def get_private_key(self) -> RSAPrivateKey:
        return self.rsa_instance.private_key

    def get_timing_samples(self) -> List[TimingSample]:
        return self.timing_samples



class DhemAttack:
    """
    Implementation of the Dhem et al. timing attack against RSA.
    """

    class Oracle:
        """
        Predicts whether a Montgomery multiplication will require an extra reduction step,
        which corresponds to predicting a "slow" operation.
        """

        def __init__(self, modulus: int):
            self.modulus = modulus
            self.k = modulus.bit_length()
            self.R = 1 << self.k
            self.n_prime = self.R - pow(self.modulus, -1, self.R)

        def predict_reduction_needed(self, a: int, b: int) -> bool:
            """
            Predicts if montgomery_multiply(a, b) will need a final subtraction by
            simulating the internal steps of the algorithm.
            """
            t = a * b
            m = ((t & (self.R - 1)) * self.n_prime) & (self.R - 1)
            u = (t + m * self.modulus) >> self.k
            return u >= self.modulus

    class MontgomerySimulator:
        """
        Simulates Montgomery arithmetic to compute intermediate states of the RSA decryption.
        This is the attacker's internal tool to model the target's behavior.
        """

        def __init__(self, modulus: int):
            self.modulus = modulus
            self.k = modulus.bit_length()
            self.R = 1 << self.k
            self.n_prime = self.R - pow(self.modulus, -1, self.R)
            self.one_mont = self.R % self.modulus

        def to_montgomery(self, x: int) -> int:
            return (x * self.R) % self.modulus

        def montgomery_reduce(self, t: int) -> int:
            m = ((t & (self.R - 1)) * self.n_prime) & (self.R - 1)
            u = (t + m * self.modulus) >> self.k
            return u - self.modulus if u >= self.modulus else u

        def montgomery_multiply(self, a_mont: int, b_mont: int) -> int:
            return self.montgomery_reduce(a_mont * b_mont)

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.oracle: Optional[DhemAttack.Oracle] = None
        self.montgomery: Optional[DhemAttack.MontgomerySimulator] = None

    def attack(self, public_key: RSAPublicKey, private_key: RSAPrivateKey,
               timing_samples: List[TimingSample]) -> bool:
        """
        Executes the Dhem timing attack to recover the private key bit by bit.
        """
        self.oracle = self.Oracle(public_key.n)
        self.montgomery = self.MontgomerySimulator(public_key.n)

        real_private_key_bits = bin(private_key.d)[2:]
        key_length = len(real_private_key_bits)

        if self.verbose:
            print(f"Starting attack on {key_length}-bit private key using {len(timing_samples)} samples.")

        known_bits = "1"

        for bit_position in range(1, key_length - 1):
            if self.verbose:
                print(f"Attacking bit {bit_position} (key index {key_length - 1 - bit_position})...")
            guessed_bit = self._find_next_bit(known_bits, timing_samples)
            known_bits += guessed_bit
            if self.verbose:
                print(f"  -> Decision: bit {bit_position} = {guessed_bit}")


        known_bits += "1"  # The last bit is always 1 as the private key must be odd
        if self.verbose:
            print("Deducing last bit as 1 (private key must be odd).")

        success = (real_private_key_bits == known_bits)
        if self.verbose:
            print("\n" + "=" * 50)
            print(f"Real private key:      {real_private_key_bits}")
            print(f"Recovered private key: {known_bits}")
            print(f"Attack {'SUCCESS' if success else 'FAILED'}")
            print("=" * 50)

        return success


    def _find_next_bit(self, known_bits: str, timing_samples: List[TimingSample]) -> str:
        """
        Finds the next unknown bit by iterating through all samples, fully processing
        each one individually to partition them based on two oracle hypotheses.
        """
        M1, M2, M3, M4 = [], [], [], []

        # Main loop: iterate through each collected timing sample.
        for sample in timing_samples:
            # For this sample, compute its m_temp and base_mont from scratch.

            base_mont = self.montgomery.to_montgomery(sample.ciphertext)

            # Step 2: Simulate the exponentiation based on known_bits.
            # The initial state for the loop is m^1.
            current_result_mont = base_mont

            for bit_char in known_bits[1:]:
                current_result_mont = self.montgomery.montgomery_multiply(current_result_mont, current_result_mont)
                if bit_char == '1':
                    current_result_mont = self.montgomery.montgomery_multiply(current_result_mont, base_mont)

            # The final result is 'm_temp', returned alongside 'base_mont' for convenience.
            m_temp = current_result_mont

            # The next operation in the algorithm is always a square.
            squared_m_temp = self.montgomery.montgomery_multiply(m_temp, m_temp)

            # --- Hypothesis: next bit is 1 (Oracle O1) ---
            after_mult_hyp1 = self.montgomery.montgomery_multiply(squared_m_temp, base_mont)
            if self.oracle.predict_reduction_needed(after_mult_hyp1, after_mult_hyp1):
                M1.append(sample.timing)
            else:
                M2.append(sample.timing)

            # --- Hypothesis: next bit is 0 (Oracle O2) ---
            if self.oracle.predict_reduction_needed(squared_m_temp, squared_m_temp):
                M3.append(sample.timing)
            else:
                M4.append(sample.timing)

        # After partitioning all samples, compare the statistical differences.
        diff_hyp1 = abs(np.mean(M1) - np.mean(M2)) if M1 and M2 else 0
        diff_hyp0 = abs(np.mean(M3) - np.mean(M4)) if M3 and M4 else 0

        if self.verbose:
            print(f"  Hypothesis 1 (bit=1): Δ_mean = {diff_hyp1:.4e}")
            print(f"  Hypothesis 0 (bit=0): Δ_mean = {diff_hyp0:.4e}")

        return "1" if diff_hyp1 > diff_hyp0 else "0"

# --- Main Execution ---

def main():
    """
    Main function demonstrating a single Dhem timing attack.
    """
    # Attack parameters
    KEY_LENGTH = 64
    SLEEP_DURATION = 0.00005 #0.00005  # 50 microseconds
    NUM_TRACES = 10000
    INITIAL_SEED = 42

    print("Dhem Timing Attack Demonstration")
    print("=" * 50)
    print(f"Key length: {KEY_LENGTH} bits")
    print(f"Sleep duration: {SLEEP_DURATION * 1e6:.0f} µs")
    print(f"Number of traces: {NUM_TRACES}")
    print("=" * 50)

    print("\nCollecting samples...")
    env = AttackEnvironment(KEY_LENGTH, SLEEP_DURATION, NUM_TRACES)

    print("\nExecuting Dhem attack...")
    attack = DhemAttack(verbose=True)
    attack.attack(
        env.get_public_key(),
        env.get_private_key(),
        env.get_timing_samples()
    )


if __name__ == "__main__":
    main()