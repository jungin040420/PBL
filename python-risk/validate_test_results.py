import csv
import sys
from collections import Counter
from pathlib import Path


RESULT_FILE = Path(
    "test_results/ml_test_results_90.csv"
)

EXPECTED_TOTAL = 90

EXPECTED_SCENARIOS = {
    "NORMAL": 50,
    "MEDIUM": 25,
    "HIGH": 15,
}


def to_bool(value: str) -> bool:
    return value.strip().lower() == "true"


def load_rows() -> list[dict]:
    if not RESULT_FILE.exists():
        raise FileNotFoundError(
            f"테스트 결과 파일이 없습니다: {RESULT_FILE}"
        )

    with RESULT_FILE.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as file:
        return list(
            csv.DictReader(file)
        )


def main() -> None:
    rows = load_rows()

    errors = []

    # ========================================================
    # 1. 전체 테스트 수 검증
    # ========================================================

    if len(rows) != EXPECTED_TOTAL:
        errors.append(
            f"전체 테스트 수 오류: "
            f"{len(rows)}건 / 예상 {EXPECTED_TOTAL}건"
        )


    # ========================================================
    # 2. 시나리오별 개수 검증
    # ========================================================

    scenario_counts = Counter(
        row["scenario_type"]
        for row in rows
    )

    for scenario, expected_count in (
        EXPECTED_SCENARIOS.items()
    ):
        actual_count = scenario_counts[
            scenario
        ]

        if actual_count != expected_count:
            errors.append(
                f"{scenario} 개수 오류: "
                f"{actual_count}건 / "
                f"예상 {expected_count}건"
            )


    # ========================================================
    # 3. TEST 데이터인지 검증
    # ========================================================

    invalid_source = [
        row["test_id"]
        for row in rows
        if row["data_source"] != "TEST"
    ]

    if invalid_source:
        errors.append(
            "data_source가 TEST가 아닌 행 존재: "
            + ", ".join(
                invalid_source
            )
        )


    # ========================================================
    # 4. Rule 테스트 PASS/FAIL 검증
    # ========================================================

    fail_rows = [
        row
        for row in rows
        if row["test_result"] != "PASS"
    ]

    if fail_rows:
        errors.append(
            f"Rule 테스트 FAIL 존재: "
            f"{len(fail_rows)}건"
        )


    # ========================================================
    # 5. 예상 Action == 실제 Action 검증
    # ========================================================

    action_mismatch = [
        row
        for row in rows
        if (
            row["expected_action"]
            != row["actual_action"]
        )
    ]

    if action_mismatch:
        errors.append(
            f"Expected/Actual Action 불일치: "
            f"{len(action_mismatch)}건"
        )


    # ========================================================
    # 6. ML 결과 누락 검증
    # ========================================================

    missing_ml_score = [
        row["test_id"]
        for row in rows
        if not row["ml_anomaly_score"]
    ]

    if missing_ml_score:
        errors.append(
            f"ML anomaly score 누락: "
            f"{len(missing_ml_score)}건"
        )


    # ========================================================
    # 7. NORMAL 오탐 확인
    # ========================================================

    normal_rows = [
        row
        for row in rows
        if row["scenario_type"]
        == "NORMAL"
    ]

    normal_anomalies = sum(
        1
        for row in normal_rows
        if to_bool(
            row["ml_is_anomaly"]
        )
    )


    # ========================================================
    # 8. MEDIUM 탐지 확인
    # ========================================================

    medium_rows = [
        row
        for row in rows
        if row["scenario_type"]
        == "MEDIUM"
    ]

    medium_anomalies = sum(
        1
        for row in medium_rows
        if to_bool(
            row["ml_is_anomaly"]
        )
    )


    # ========================================================
    # 9. HIGH 탐지 확인
    # ========================================================

    high_rows = [
        row
        for row in rows
        if row["scenario_type"]
        == "HIGH"
    ]

    high_anomalies = sum(
        1
        for row in high_rows
        if to_bool(
            row["ml_is_anomaly"]
        )
    )


    # ========================================================
    # 결과 출력
    # ========================================================

    print("=" * 70)
    print("90건 테스트 결과 자동 검증")
    print("=" * 70)

    print(
        f"전체 테스트: "
        f"{len(rows)} / {EXPECTED_TOTAL}"
    )

    print(
        f"NORMAL: "
        f"{scenario_counts['NORMAL']} / 50"
    )

    print(
        f"MEDIUM: "
        f"{scenario_counts['MEDIUM']} / 25"
    )

    print(
        f"HIGH: "
        f"{scenario_counts['HIGH']} / 15"
    )

    print()

    print(
        f"Rule PASS: "
        f"{len(rows) - len(fail_rows)}"
    )

    print(
        f"Rule FAIL: "
        f"{len(fail_rows)}"
    )

    print()

    print(
        f"NORMAL ML 이상 탐지: "
        f"{normal_anomalies} / "
        f"{len(normal_rows)}"
    )

    print(
        f"MEDIUM ML 이상 탐지: "
        f"{medium_anomalies} / "
        f"{len(medium_rows)}"
    )

    print(
        f"HIGH ML 이상 탐지: "
        f"{high_anomalies} / "
        f"{len(high_rows)}"
    )

    print()


    if errors:
        print("[검증 실패]")

        for error in errors:
            print(
                f"- {error}"
            )

        sys.exit(1)


    print("[검증 성공]")
    print(
        "90건 시나리오 테스트 결과가 "
        "정의된 기준과 일치합니다."
    )

    print("=" * 70)


if __name__ == "__main__":
    main()