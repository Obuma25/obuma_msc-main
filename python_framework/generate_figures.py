#!/usr/bin/env python3
"""
Generate dissertation figures from test results using seaborn.
Outputs PNG files into a 'figures/' directory.
"""

import json
from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns

# --- Setup ---
sns.set_theme(style="whitegrid", font_scale=1.15)
plt.rcParams.update({
    "figure.dpi": 300,
    "savefig.dpi": 300,
    "font.family": "serif",
    "axes.edgecolor": "#333333",
    "axes.linewidth": 0.8,
})

BASE_DIR = Path(__file__).resolve().parents[2]
OUTPUT_DIR = BASE_DIR / "figures"
OUTPUT_DIR.mkdir(exist_ok=True)

# --- Load results ---
SQLI_FILE = Path(__file__).resolve().parent / "sqli_test_results_20260325_132232.json"
DNS_FILE = Path(__file__).resolve().parent / "dns_exfil_test_results_20260325_161140.json"

with open(SQLI_FILE) as f:
    sqli_data = json.load(f)

with open(DNS_FILE) as f:
    dns_data = json.load(f)

sqli_results = sqli_data["test_results"]
dns_results = dns_data["test_results"]


# ============================================================
# FIGURE 1: Detection Rate Comparison (SQLi vs DNS)
# ============================================================
def fig1_detection_rate_comparison():
    categories = ["SQL Injection\n(Application Layer)", "DNS Exfiltration\n(Network Layer)"]
    detection_rates = [0.0, 11.1]
    false_neg_rates = [100.0, 88.9]
    colours = [sns.color_palette("muted")[3], sns.color_palette("muted")[0]]

    fig, ax = plt.subplots(figsize=(7, 5))
    bars = ax.bar(categories, detection_rates, width=0.5, color=colours,
                  edgecolor="#333333", linewidth=0.8, zorder=3)

    # Add percentage labels on bars
    for bar, rate in zip(bars, detection_rates):
        ypos = bar.get_height() + 1.5
        ax.text(bar.get_x() + bar.get_width() / 2, ypos,
                f"{rate:.1f}%", ha="center", va="bottom",
                fontweight="bold", fontsize=14)

    ax.set_ylabel("Detection Rate (%)", fontsize=12)
    ax.set_title("GuardDuty Detection Rate by Attack Class", fontsize=13, fontweight="bold")
    ax.set_ylim(0, 50)
    ax.yaxis.set_major_locator(plt.MultipleLocator(10))

    # Add sample size annotations
    ax.text(0, -6, "n = 10", ha="center", fontsize=10, color="#555555")
    ax.text(1, -6, "n = 9", ha="center", fontsize=10, color="#555555")

    sns.despine(left=False, bottom=False)
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "fig_detection_rate_comparison.png", bbox_inches="tight")
    plt.close()
    print("[OK] Figure 1: Detection rate comparison")


# ============================================================
# FIGURE 2: SQLi Response Times by Technique
# ============================================================
def fig2_sqli_response_times():
    rows = []
    for r in sqli_results:
        rows.append({
            "Test ID": r["test_id"],
            "Technique": r["technique"].replace(" (Auth Bypass)", "\n(Auth Bypass)"),
            "Response Time (ms)": r["attack_details"]["response_time_ms"],
            "HTTP Status": r["attack_details"]["status_code"],
            "Detected": "Detected" if r["detected"] else "Not Detected"
        })
    df = pd.DataFrame(rows)

    fig, ax = plt.subplots(figsize=(10, 5))
    palette = {"Not Detected": sns.color_palette("muted")[3]}
    sns.barplot(data=df, x="Test ID", y="Response Time (ms)",
                hue="Detected", palette=palette, edgecolor="#333333",
                linewidth=0.8, ax=ax, legend=False, zorder=3)

    # Add HTTP status code labels on each bar
    for i, row in df.iterrows():
        ax.text(i, row["Response Time (ms)"] + 15,
                f"HTTP {row['HTTP Status']}",
                ha="center", va="bottom", fontsize=8, color="#555555")

    ax.set_ylabel("Response Time (ms)", fontsize=11)
    ax.set_xlabel("")
    ax.set_title("SQL Injection Attack Response Times and HTTP Status Codes",
                 fontsize=12, fontweight="bold")

    # Add "0% Detected" annotation
    ax.text(0.5, 0.95, "GuardDuty Detection: 0/10 (0%)",
            transform=ax.transAxes, ha="center", va="top",
            fontsize=11, color=sns.color_palette("muted")[3],
            fontweight="bold",
            bbox=dict(boxstyle="round,pad=0.3", facecolor="#fce4e4", edgecolor="#cc0000", alpha=0.8))

    sns.despine()
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "fig_sqli_response_times.png", bbox_inches="tight")
    plt.close()
    print("[OK] Figure 2: SQLi response times")


# ============================================================
# FIGURE 3: DNS Test Parameters - Bubble Chart
# ============================================================
def fig3_dns_parameters_bubble():
    rows = []
    for r in dns_results:
        if r["attack_executed"] or r["attack_details"].get("success", False):
            success = r["attack_details"].get("success", False)
            if not success:
                continue
            rows.append({
                "Test ID": r["test_id"],
                "Data Volume (KB)": r["data_size_kb"],
                "Query Rate (QPS)": r["queries_per_second"],
                "Total Queries": r["attack_details"]["queries_sent"],
                "Detected": "Detected" if r["detected"] else "Not Detected"
            })
    df = pd.DataFrame(rows)

    fig, ax = plt.subplots(figsize=(8, 6))
    palette = {"Detected": sns.color_palette("muted")[2],
               "Not Detected": sns.color_palette("muted")[3]}

    sns.scatterplot(data=df, x="Query Rate (QPS)", y="Data Volume (KB)",
                    size="Total Queries", hue="Detected",
                    sizes=(100, 800), palette=palette,
                    edgecolor="#333333", linewidth=0.8, ax=ax, zorder=3)

    # Label each point with test ID
    for _, row in df.iterrows():
        ax.annotate(row["Test ID"],
                    (row["Query Rate (QPS)"], row["Data Volume (KB)"]),
                    textcoords="offset points", xytext=(8, 8),
                    fontsize=8, color="#333333")

    ax.set_title("DNS Exfiltration Test Parameters and Detection Outcomes",
                 fontsize=12, fontweight="bold")
    ax.set_xlabel("Query Rate (queries/second)", fontsize=11)
    ax.set_ylabel("Data Volume (KB)", fontsize=11)

    handles, labels = ax.get_legend_handles_labels()
    # Keep only Detected/Not Detected in legend
    new_handles = []
    new_labels = []
    for h, l in zip(handles, labels):
        if l in ["Detected", "Not Detected"]:
            new_handles.append(h)
            new_labels.append(l)
    ax.legend(new_handles, new_labels, title="Detection", loc="upper left")

    sns.despine()
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "fig_dns_parameters_bubble.png", bbox_inches="tight")
    plt.close()
    print("[OK] Figure 3: DNS parameters bubble chart")


# ============================================================
# FIGURE 4: DNS Test Timeline
# ============================================================
def fig4_dns_timeline():
    rows = []
    for r in dns_results:
        ad = r["attack_details"]
        success = ad.get("success", False)
        rows.append({
            "Test ID": r["test_id"],
            "Queries Sent": ad.get("queries_sent", 0),
            "Duration (s)": ad.get("total_time_seconds", 0),
            "Detected": "Detected" if r["detected"] else ("Failed" if not success else "Not Detected"),
            "Success": success
        })
    df = pd.DataFrame(rows)

    fig, ax = plt.subplots(figsize=(10, 5))
    colour_map = {"Detected": sns.color_palette("muted")[2],
                  "Not Detected": sns.color_palette("muted")[0],
                  "Failed": "#aaaaaa"}
    colours = [colour_map[d] for d in df["Detected"]]

    bars = ax.bar(df["Test ID"], df["Queries Sent"], color=colours,
                  edgecolor="#333333", linewidth=0.8, zorder=3)

    # Mark detected test
    for i, row in df.iterrows():
        if row["Detected"] == "Detected":
            ax.annotate("DETECTED\n(2.40s TTD)",
                        xy=(i, row["Queries Sent"]),
                        xytext=(i + 0.5, row["Queries Sent"] + 600),
                        fontsize=9, fontweight="bold",
                        color=sns.color_palette("muted")[2],
                        arrowprops=dict(arrowstyle="->",
                                        color=sns.color_palette("muted")[2],
                                        lw=1.5),
                        ha="center")
        elif row["Detected"] == "Failed":
            ax.text(i, 150, "SSM\nTimeout", ha="center", fontsize=8,
                    color="#777777", fontstyle="italic")

    ax.set_ylabel("DNS Queries Sent", fontsize=11)
    ax.set_xlabel("")
    ax.set_title("DNS Exfiltration Queries per Test Scenario with Detection Outcome",
                 fontsize=12, fontweight="bold")

    # Legend
    legend_elements = [
        mpatches.Patch(facecolor=colour_map["Detected"], edgecolor="#333",
                       label="Detected"),
        mpatches.Patch(facecolor=colour_map["Not Detected"], edgecolor="#333",
                       label="Not Detected"),
        mpatches.Patch(facecolor=colour_map["Failed"], edgecolor="#333",
                       label="Execution Failed"),
    ]
    ax.legend(handles=legend_elements, loc="upper right")

    sns.despine()
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "fig_dns_timeline.png", bbox_inches="tight")
    plt.close()
    print("[OK] Figure 4: DNS test timeline")


# ============================================================
# FIGURE 5: Confidence Intervals Comparison
# ============================================================
def fig5_confidence_intervals():
    data = {
        "Attack Class": [
            "SQL Injection\n(n=10)",
            "DNS Exfiltration\n(n=9)"
        ],
        "Detection Rate": [0.0, 11.1],
        "CI Lower": [0.0, 0.3],
        "CI Upper": [30.8, 48.2]
    }
    df = pd.DataFrame(data)

    fig, ax = plt.subplots(figsize=(7, 4.5))
    colours = [sns.color_palette("muted")[3], sns.color_palette("muted")[0]]

    # Plot points
    for i, row in df.iterrows():
        ax.plot(row["Detection Rate"], i, "o", color=colours[i],
                markersize=12, zorder=5, markeredgecolor="#333333", markeredgewidth=1)
        # CI line
        ax.plot([row["CI Lower"], row["CI Upper"]], [i, i],
                color=colours[i], linewidth=2.5, zorder=4)
        # CI caps
        for val in [row["CI Lower"], row["CI Upper"]]:
            ax.plot([val, val], [i - 0.1, i + 0.1],
                    color=colours[i], linewidth=2, zorder=4)
        # Label
        ax.text(row["CI Upper"] + 2, i,
                f"{row['Detection Rate']:.1f}%  [{row['CI Lower']:.1f}%, {row['CI Upper']:.1f}%]",
                va="center", fontsize=10, fontweight="bold")

    ax.set_yticks(range(len(df)))
    ax.set_yticklabels(df["Attack Class"])
    ax.set_xlabel("Detection Rate (%)", fontsize=11)
    ax.set_title("95% Clopper-Pearson Confidence Intervals for Detection Rates",
                 fontsize=12, fontweight="bold")
    ax.set_xlim(-5, 70)
    ax.axvline(x=50, color="#999999", linestyle="--", linewidth=0.8, label="50% (chance level)")
    ax.legend(loc="lower right", fontsize=9)

    sns.despine(left=True)
    ax.tick_params(left=False)
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "fig_confidence_intervals.png", bbox_inches="tight")
    plt.close()
    print("[OK] Figure 5: Confidence intervals")


# ============================================================
# FIGURE 6: Overall Summary Heatmap
# ============================================================
def fig6_summary_heatmap():
    techniques = [
        "Boolean-based blind", "UNION-based", "Time-based blind",
        "Error-based", "DNS (10 KB-50 KB)", "DNS (75 KB-200 KB)"
    ]
    metrics = ["Attack\nSuccess", "GuardDuty\nDetection"]

    # 1 = success/detected, 0 = fail/not detected, 0.5 = partial
    data = np.array([
        [1, 0],   # Boolean blind - all succeeded, none detected
        [1, 0],   # UNION - all succeeded, none detected
        [1, 0],   # Time-based - all succeeded, none detected
        [1, 0],   # Error-based - all succeeded, none detected
        [1, 0.33],   # DNS small - 3/3 success, 1/3 detected (EX-01)
        [0.83, 0],   # DNS large - 5/6 success (EX-10 failed), 0 detected
    ])

    fig, ax = plt.subplots(figsize=(6, 5.5))
    cmap = sns.diverging_palette(10, 130, s=80, l=55, as_cmap=True)
    sns.heatmap(data, annot=False, cmap=cmap, vmin=0, vmax=1,
                xticklabels=metrics, yticklabels=techniques,
                linewidths=1.5, linecolor="white",
                cbar_kws={"label": "Rate (0 = None, 1 = All)", "shrink": 0.8},
                ax=ax)

    # Custom annotations
    labels = [
        ["4/4 (100%)", "0/4 (0%)"],
        ["2/2 (100%)", "0/2 (0%)"],
        ["2/2 (100%)", "0/2 (0%)"],
        ["2/2 (100%)", "0/2 (0%)"],
        ["3/3 (100%)", "1/3 (33%)"],
        ["5/6 (83%)", "0/6 (0%)"],
    ]
    for i in range(len(techniques)):
        for j in range(len(metrics)):
            colour = "white" if data[i, j] < 0.4 else "#333333"
            ax.text(j + 0.5, i + 0.5, labels[i][j],
                    ha="center", va="center", fontsize=9,
                    fontweight="bold", color=colour)

    ax.set_title("Attack Success vs GuardDuty Detection by Technique",
                 fontsize=12, fontweight="bold", pad=12)
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "fig_summary_heatmap.png", bbox_inches="tight")
    plt.close()
    print("[OK] Figure 6: Summary heatmap")


# ============================================================
# RUN ALL
# ============================================================
if __name__ == "__main__":
    print("Generating dissertation figures...\n")
    fig1_detection_rate_comparison()
    fig2_sqli_response_times()
    fig3_dns_parameters_bubble()
    fig4_dns_timeline()
    fig5_confidence_intervals()
    fig6_summary_heatmap()
    print(f"\nAll figures saved to '{OUTPUT_DIR}/' directory.")
    print("\nYou still need to take these SCREENSHOTS from the AWS console:")
    print("  1. GuardDuty Findings page showing the DGADomainRequest.B finding")
    print("  2. Click into the finding to show the detail panel")
    print("  3. GuardDuty Summary/dashboard page")
    print("  4. EC2 instance page showing i-0c133dabd8f80c99e")
