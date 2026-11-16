from __future__ import annotations

import csv
import random
import statistics
import sys
import time
from pathlib import Path

import matplotlib.pyplot as plt

# Ensure local python/src is prioritized when running directly from the repo
_SRC_DIR = Path(__file__).resolve().parents[1] / "python" / "src"
if _SRC_DIR.exists():
    sys.path.insert(0, str(_SRC_DIR))

from dslrs.core import SystemParameters, deanonymize, link, sign, verify
from dslrs.utils import generate_shares

if __name__ == "__main__":
    K_values = [8, 16, 32]
    runs_per_K = 100
    csv_filename = "protocol_benchmarks.csv"

    avg_results: dict[str, list[float]] = {
        "Sign": [],
        "Verify": [],
        "Link": [],
        "Deanonymize": [],
    }

    print(f"Starting execution using optimized `dslrs` package. Results will be saved to {csv_filename} and benchmark_plot.png")

    with open(csv_filename, mode="w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["K", "Run", "Sign_Time_s", "Verify_Time_s", "Link_Time_s", "Deanonymize_Time_s"])

        for K in K_values:
            sign_latencies: list[float] = []
            verify_latencies: list[float] = []
            link_latencies: list[float] = []
            deanonymize_latencies: list[float] = []

            for run in range(1, runs_per_K + 1):
                PP = SystemParameters()
                N = 12
                k = 8
                all_shares = generate_shares(PP.S_net, N, k, PP.q, PP.G)

                S_keys = []
                P_keys = []

                for _ in range(K):
                    s = random.randint(1, PP.q - 1)
                    S_keys.append(s)
                    P_keys.append(s * PP.G)

                L = P_keys
                PP.L_registry.append(L)

                s_index = 1
                signer_S = S_keys[s_index]
                m_1 = "Consent_proof_V1"
                m_2 = "Consent_proof_V2"

                SID_A = PP.SIDs[0]

                # Measure Sign
                start_time = time.perf_counter()
                sigma_1 = sign(m_1, signer_S, L, SID_A, PP)
                sign_time = time.perf_counter() - start_time
                sign_latencies.append(sign_time)

                sigma_2 = sign(m_2, signer_S, L, SID_A, PP)

                # Measure Verify
                start_time = time.perf_counter()
                verify(m_1, sigma_1, PP)
                verify_time = time.perf_counter() - start_time
                verify_latencies.append(verify_time)

                # Measure Link
                start_time = time.perf_counter()
                link(sigma_1, m_1, sigma_2, m_2, PP)
                link_time = time.perf_counter() - start_time
                link_latencies.append(link_time)

                # Setup Deanonymize
                responding_nodes = random.sample(all_shares, k)
                omega_list = []
                D_list = []
                for node in responding_nodes:
                    D_j = node["S_net_j"] * sigma_1[4]  # type: ignore[index]
                    omega_list.append(node["omega"])
                    D_list.append(D_j)

                # Measure Deanonymize
                start_time = time.perf_counter()
                deanonymize(sigma_1, D_list, omega_list, PP.q)  # type: ignore[arg-type]
                deanonymize_time = time.perf_counter() - start_time
                deanonymize_latencies.append(deanonymize_time)

                writer.writerow([K, run, sign_time, verify_time, link_time, deanonymize_time])

            avg_sign = statistics.mean(sign_latencies)
            avg_verify = statistics.mean(verify_latencies)
            avg_link = statistics.mean(link_latencies)
            avg_deanonymize = statistics.mean(deanonymize_latencies)

            avg_results["Sign"].append(avg_sign)
            avg_results["Verify"].append(avg_verify)
            avg_results["Link"].append(avg_link)
            avg_results["Deanonymize"].append(avg_deanonymize)

            print(f"--- K = {K} ---")
            print(
                f"Sign: {avg_sign:.4f}s, Verify: {avg_verify:.4f}s, "
                f"Link: {avg_link:.4f}s, Dean: {avg_deanonymize:.4f}s"
            )

    # Generate the bar plot
    x = range(len(K_values))
    width = 0.2

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.bar([pos - 1.5 * width for pos in x], avg_results["Sign"], width, label="Sign")
    ax.bar([pos - 0.5 * width for pos in x], avg_results["Verify"], width, label="Verify")
    ax.bar([pos + 0.5 * width for pos in x], avg_results["Link"], width, label="Link")
    ax.bar([pos + 1.5 * width for pos in x], avg_results["Deanonymize"], width, label="Deanonymize")

    ax.set_ylabel("Average Latency (seconds)")
    ax.set_xlabel("Number of Keys in Global Registry (K)")
    ax.set_title("Average Cryptographic Operation Latency by K (100 runs each)")
    ax.set_xticks(list(x))
    ax.set_xticklabels(K_values)
    ax.legend()
    plt.grid(axis="y", linestyle="--", alpha=0.7)
    plt.tight_layout()

    plt.savefig("benchmark_plot.png")
    print("Plot successfully saved to benchmark_plot.png")
