import pandas as pd


def calculate_benchmark_statistics(csv_filename="protocol_benchmarks.csv"):
    try:
        df = pd.read_csv(csv_filename)
    except FileNotFoundError:
        print(f"Error: Could not find '{csv_filename}'. Ensure it is in the same directory.")
        return

    operation_cols = [
        "Sign_Time_s",
        "Verify_Time_s",
        "Link_Time_s",
        "Deanonymize_Time_s",
    ]

    missing_cols = [col for col in operation_cols if col not in df.columns]
    if missing_cols:
        print(f"Error: Missing expected columns in CSV: {missing_cols}")
        return

    summary_stats = df.groupby("K")[operation_cols].agg(["mean", "median"])
    summary_stats.columns = [f"{col.split('_')[0]}_{stat.capitalize()}" for col, stat in summary_stats.columns]

    print("=== Cryptographic Performance Statistics by K (Seconds) ===")
    print(summary_stats.to_string())
    print("\n=== Cryptographic Performance Statistics by K (Milliseconds) ===")
    print((summary_stats * 1000).round(2).to_string())
    print("===========================================================")


if __name__ == "__main__":
    calculate_benchmark_statistics()
