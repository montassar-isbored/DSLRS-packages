import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns


def generate_distribution_plots(
    csv_filename="protocol_benchmarks.csv",
    output_img="distributionboxplot.png",
):
    try:
        df = pd.read_csv(csv_filename)
    except FileNotFoundError:
        print(f"Error: Could not find '{csv_filename}'. Ensure it is in the same directory.")
        return

    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle("", fontsize=1)

    operations = [
        ("Sign_Time_s", "Sign Latency", axes[0, 0]),
        ("Verify_Time_s", "Verify Latency", axes[0, 1]),
        ("Link_Time_s", "Link Latency", axes[1, 0]),
        ("Deanonymize_Time_s", "Deanonymize Latency", axes[1, 1]),
    ]

    sns.set_theme(style="whitegrid")

    for col, title, ax in operations:
        sns.boxplot(
            data=df,
            x="K",
            y=col,
            ax=ax,
            palette="Set2",
            showmeans=True,
            showfliers=False,
            meanprops={
                "marker": "o",
                "markerfacecolor": "white",
                "markeredgecolor": "black",
                "markersize": "6",
            },
        )

        ax.set_title(title, fontsize=14)
        ax.set_ylabel("Time (seconds)", fontsize=12)
        ax.set_xlabel("Ring Size (n)", fontsize=12)

    plt.tight_layout()
    plt.subplots_adjust(top=0.92)
    plt.savefig(output_img, dpi=300)
    print(f"Plot saved to {output_img}")


if __name__ == "__main__":
    generate_distribution_plots()
