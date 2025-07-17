import random
import time
import csv
import multiprocessing
import os
from datetime import datetime
from typing import List, Tuple, Dict

from dhem_attack import AttackEnvironment, DhemAttack


class ExperimentRunner:
    """
    Orchestrates parallel execution of Dhem timing attack experiments.
    """

    def __init__(self, key_sizes: List[int], sleep_durations: List[float],
                 trace_counts: List[int], num_keys_per_trial: int = 50):
        self.key_sizes = key_sizes
        self.sleep_durations = sleep_durations
        self.trace_counts = trace_counts
        self.num_keys_per_trial = num_keys_per_trial

    def run_all_experiments(self) -> None:
        """
        Executes all experiment campaigns, one for each key size.
        """
        campaign_start_time = time.time()
        print("🚀 Starting all experiment campaigns...")

        for key_size in self.key_sizes:
            print(f"\n{'=' * 70}")
            print(f"🔬 RUNNING CAMPAIGN FOR {key_size}-BIT KEYS")
            print(f"{'=' * 70}")

            results = self._run_campaign(key_size)
            self._print_results_table(key_size, results)
            self._save_results_to_csv(key_size, results)

        campaign_end_time = time.time()
        print(f"\n✅ All campaigns finished in {campaign_end_time - campaign_start_time:.2f} seconds.")

    def _run_campaign(self, key_size: int) -> Dict[float, Dict[int, Dict]]:
        """
        Runs a complete campaign for a specific key size using parallel processing.
        """
        param_combinations = []
        for sleep in self.sleep_durations:
            for traces in self.trace_counts:
                param_combinations.append((key_size, sleep, traces, self.num_keys_per_trial))

        print(f"   ↳ Executing {len(param_combinations)} experiments in parallel for {key_size}-bit keys...")
        with multiprocessing.Pool() as pool:
            results_list = pool.map(self._run_single_experiment, param_combinations)

        print(f"   ↳ Campaign for {key_size}-bit keys finished. Processing results...")

        # Organize the results from the parallel processes
        results = {}
        for params, result_data in zip(param_combinations, results_list):
            _, sleep, traces, _ = params
            success_rate, avg_collection_time, avg_analysis_time = result_data

            if sleep not in results:
                results[sleep] = {}
            results[sleep][traces] = {
                'rate': success_rate,
                'collection_time': avg_collection_time,
                'analysis_time': avg_analysis_time
            }

        return results

    @staticmethod
    def _run_single_experiment(params: Tuple[int, float, int, int]) -> Tuple[float, float, float]:
        """
        Runs a single experiment, timing sample collection and analysis separately.

        Returns:
            A tuple: (success_rate_percent, avg_collection_time_s, avg_analysis_time_s).
        """
        key_size, sleep_duration, trace_count, num_keys_per_trial = params
        pid = os.getpid()

        print(
            f"      [Worker PID: {pid}] ▶️ Starting: {key_size}b, {sleep_duration * 1e6:.0f}µs sleep, {trace_count} traces...")

        total_collection_time = 0
        total_analysis_time = 0
        success_count = 0

        for _ in range(num_keys_per_trial):
            # Time the sample collection phase
            collection_start = time.time()
            env = AttackEnvironment(key_size, sleep_duration, trace_count)
            total_collection_time += (time.time() - collection_start)

            # Time the analysis phase
            analysis_start = time.time()
            attack = DhemAttack(verbose=False)
            if attack.attack(env.get_public_key(), env.get_private_key(), env.get_timing_samples()):
                success_count += 1
            total_analysis_time += (time.time() - analysis_start)

        # Calculate averages
        avg_collection_time = total_collection_time / num_keys_per_trial if num_keys_per_trial > 0 else 0
        avg_analysis_time = total_analysis_time / num_keys_per_trial if num_keys_per_trial > 0 else 0
        success_rate = (success_count / num_keys_per_trial) * 100 if num_keys_per_trial > 0 else 0

        print(
            f"      [Worker PID: {pid}] ⏹️ Finished. Success: {success_rate:.0f}%. Times (Collect/Analyze): {avg_collection_time:.2f}s / {avg_analysis_time:.2f}s")

        return success_rate, avg_collection_time, avg_analysis_time

    def _print_results_table(self, key_size: int, results: Dict[float, Dict[int, Dict]]) -> None:
        """Prints a formatted results table to the console."""
        print(f"\n--- Results for {key_size}-bit keys (Success % | Collection Time + Analysis Time) ---")
        header = f"{'Sleep (µs)':>12} |"
        for traces in self.trace_counts:
            header += f" {traces:>20} traces |"
        print(header)
        print('-' * len(header))

        for sleep, sleep_results in sorted(results.items()):
            row = f"{sleep * 1e6:>12.0f} |"
            for traces in self.trace_counts:
                if traces in sleep_results:
                    rate = sleep_results[traces]['rate']
                    t_collect = sleep_results[traces]['collection_time']
                    t_analyze = sleep_results[traces]['analysis_time']
                    row += f" {rate:>3.0f}% ({t_collect:>.1f}s + {t_analyze:>.1f}s) |"
                else:
                    row += " " * 23 + "|"
            print(row)
        print('-' * len(header))

    def _save_results_to_csv(self, key_size: int, results: Dict[float, Dict[int, Dict]]) -> None:
        """Saves the campaign results to a CSV file with separate time columns."""
        filename = f"results_{key_size}bit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['key_size_bits', 'sleep_us', 'num_traces', 'success_rate_percent', 'avg_collection_time_s',
                             'avg_analysis_time_s'])

            for sleep, sleep_results in sorted(results.items()):
                for traces, trace_results in sorted(sleep_results.items()):
                    writer.writerow([
                        key_size,
                        sleep * 1e6,
                        traces,
                        trace_results['rate'],
                        trace_results['collection_time'],
                        trace_results['analysis_time']
                    ])

        print(f"\nResults for {key_size}-bit keys saved to: {filename}")




if __name__ == "__main__":
    # Define the parameters for the experiment campaigns
    KEY_SIZES = [64, 128]
    #SLEEP_DURATIONS = [0.0, 0.00001, 0.00005]  # 0µs, 10µs, 50µs
    SLEEP_DURATIONS = [0, 0.00001, 0.00005, 0.0001]
    #TRACE_COUNTS = [40000, 80000]
    TRACE_COUNTS = [10000, 20000, 40000, 80000, 160000]
    NUM_KEYS_PER_TRIAL = 10  # Use a smaller number for quicker tests


    GLOBAL_SEED = 42
    random.seed(GLOBAL_SEED)

    runner = ExperimentRunner(
        key_sizes=KEY_SIZES,
        sleep_durations=SLEEP_DURATIONS,
        trace_counts=TRACE_COUNTS,
        num_keys_per_trial=NUM_KEYS_PER_TRIAL
    )
    runner.run_all_experiments()