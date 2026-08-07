import csv
from collections import Counter, defaultdict
from pathlib import Path


RESULT_FILE = Path(
    "test_results/ml_test_results_90.csv"
)

SUMMARY_FILE = Path(
    "test_results/ml_test_summary.csv"
)


def load_rows() -> list[dict]:
    if not RESULT_FILE.exists():
        raise FileNotFoundError(
            f"결과 파일이 없습니다: {RESULT_FILE}"
        )

    with RESULT_FILE.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as file:
        return list(
            csv.DictReader(file)
        )


def to_bool(value: str) -> bool:
    return (
        value.strip().lower()
        == "true"
    )


def build_summary(
    rows: list[dict],
) -> list[dict]:

    scenario_counts = Counter()
    anomaly_counts = Counter()
    pass_counts = Counter()

    rule_score_sum = defaultdict(float)
    ml_score_sum = defaultdict(float)
    ml_score_count = Counter()

    for row in rows:
        scenario = row[
            "scenario_type"
        ]

        scenario_counts[
            scenario
        ] += 1

        if (
            row["test_result"]
            == "PASS"
        ):
            pass_counts[
                scenario
            ] += 1

        rule_score_sum[
            scenario
        ] += float(
            row["rule_score"]
        )

        if to_bool(
            row["ml_is_anomaly"]
        ):
            anomaly_counts[
                scenario
            ] += 1

        if row[
            "ml_anomaly_score"
        ]:
            ml_score_sum[
                scenario
            ] += float(
                row[
                    "ml_anomaly_score"
                ]
            )

            ml_score_count[
                scenario
            ] += 1


    summary = []

    for scenario in [
        "NORMAL",
        "MEDIUM",
        "HIGH",
    ]:

        total = scenario_counts[
            scenario
        ]

        passed = pass_counts[
            scenario
        ]

        failed = (
            total - passed
        )

        anomalies = anomaly_counts[
            scenario
        ]

        anomaly_rate = (
            anomalies
            / total
            * 100
            if total
            else 0
        )

        average_rule_score = (
            rule_score_sum[
                scenario
            ]
            / total
            if total
            else 0
        )

        average_ml_score = (
            ml_score_sum[
                scenario
            ]
            / ml_score_count[
                scenario
            ]
            if ml_score_count[
                scenario
            ]
            else 0
        )

        summary.append(
            {
                "scenario_type":
                    scenario,

                "test_count":
                    total,

                "pass_count":
                    passed,

                "fail_count":
                    failed,

                "pass_rate_percent":
                    round(
                        (
                            passed
                            / total
                            * 100
                        )
                        if total
                        else 0,
                        2,
                    ),

                "ml_anomaly_count":
                    anomalies,

                "ml_anomaly_rate_percent":
                    round(
                        anomaly_rate,
                        2,
                    ),

                "average_rule_score":
                    round(
                        average_rule_score,
                        2,
                    ),

                "average_ml_anomaly_score":
                    round(
                        average_ml_score,
                        6,
                    ),
            }
        )

    return summary


def add_total_row(
    summary: list[dict],
) -> list[dict]:

    total_tests = sum(
        row["test_count"]
        for row in summary
    )

    total_pass = sum(
        row["pass_count"]
        for row in summary
    )

    total_fail = sum(
        row["fail_count"]
        for row in summary
    )

    total_anomaly = sum(
        row["ml_anomaly_count"]
        for row in summary
    )

    total_row = {
        "scenario_type":
            "TOTAL",

        "test_count":
            total_tests,

        "pass_count":
            total_pass,

        "fail_count":
            total_fail,

        "pass_rate_percent":
            round(
                (
                    total_pass
                    / total_tests
                    * 100
                )
                if total_tests
                else 0,
                2,
            ),

        "ml_anomaly_count":
            total_anomaly,

        "ml_anomaly_rate_percent":
            round(
                (
                    total_anomaly
                    / total_tests
                    * 100
                )
                if total_tests
                else 0,
                2,
            ),

        "average_rule_score":
            "",

        "average_ml_anomaly_score":
            "",
    }

    return (
        summary
        + [total_row]
    )


def save_summary_csv(
    summary: list[dict],
) -> None:

    SUMMARY_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fieldnames = [
        "scenario_type",
        "test_count",
        "pass_count",
        "fail_count",
        "pass_rate_percent",
        "ml_anomaly_count",
        "ml_anomaly_rate_percent",
        "average_rule_score",
        "average_ml_anomaly_score",
    ]

    with SUMMARY_FILE.open(
        "w",
        newline="",
        encoding="utf-8-sig",
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )

        writer.writeheader()

        writer.writerows(
            summary
        )


def print_summary(
    summary: list[dict],
) -> None:

    print()
    print("=" * 80)
    print(
        "90건 테스트 결과 시나리오별 요약"
    )
    print("=" * 80)

    for row in summary:

        print()

        print(
            f"[{row['scenario_type']}]"
        )

        print(
            f"테스트 수: "
            f"{row['test_count']}"
        )

        print(
            f"PASS: "
            f"{row['pass_count']}"
        )

        print(
            f"FAIL: "
            f"{row['fail_count']}"
        )

        print(
            f"PASS율: "
            f"{row['pass_rate_percent']}%"
        )

        print(
            f"ML 이상 판정: "
            f"{row['ml_anomaly_count']}"
        )

        print(
            f"ML 이상 판정률: "
            f"{row['ml_anomaly_rate_percent']}%"
        )

        if (
            row[
                "average_rule_score"
            ]
            != ""
        ):
            print(
                f"평균 Rule Score: "
                f"{row['average_rule_score']}"
            )

        if (
            row[
                "average_ml_anomaly_score"
            ]
            != ""
        ):
            print(
                f"평균 ML Anomaly Score: "
                f"{row['average_ml_anomaly_score']}"
            )

    print()
    print("=" * 80)

    print(
        "개별 결과 CSV:"
    )

    print(
        RESULT_FILE.resolve()
    )

    print()

    print(
        "회의용 요약 CSV:"
    )

    print(
        SUMMARY_FILE.resolve()
    )

    print("=" * 80)


def main() -> None:

    rows = load_rows()

    if len(rows) != 90:
        print(
            f"[경고] 현재 결과는 "
            f"{len(rows)}건입니다."
        )

    summary = build_summary(
        rows
    )

    summary = add_total_row(
        summary
    )

    save_summary_csv(
        summary
    )

    print_summary(
        summary
    )


if __name__ == "__main__":
    main()