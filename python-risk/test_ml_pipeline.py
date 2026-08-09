import csv
import os
import random
from pathlib import Path

from app.isolation_model import (
    FEATURE_ORDER,
    build_feature_vector,
    load,
    load_metadata,
)


# ============================================================
# 설정
# ============================================================

RANDOM_SEED = 42

NORMAL_COUNT = 50
MEDIUM_COUNT = 25
HIGH_COUNT = 15

TOTAL_COUNT = (
    NORMAL_COUNT
    + MEDIUM_COUNT
    + HIGH_COUNT
)

RESULT_DIR = Path("test_results")

RESULT_FILE = (
    RESULT_DIR
    / "ml_test_results_90.csv"
)


# ============================================================
# Rule-Based Risk 계산
#
# 현재 main.py의 정책과 동일하게 맞춘다.
# ============================================================

def calculate_rule_risk(
    features: dict,
) -> dict:

    score = 0
    triggers = []


    # --------------------------------------------------------
    # 로그인 빈도
    # --------------------------------------------------------

    login_frequency = int(
        features["loginFrequency"]
    )

    if login_frequency >= 10:
        score += 15
        triggers.append(
            "HIGH_LOGIN_FREQUENCY"
        )

    elif login_frequency >= 5:
        score += 10
        triggers.append(
            "HIGH_LOGIN_FREQUENCY"
        )

    elif login_frequency >= 3:
        score += 5
        triggers.append(
            "HIGH_LOGIN_FREQUENCY"
        )


    # --------------------------------------------------------
    # 로그인 실패 횟수
    # --------------------------------------------------------

    failed_count = int(
        features["failedLoginCount"]
    )

    if failed_count >= 5:
        score += 25
        triggers.append(
            "LOGIN_FAILURE"
        )

    elif failed_count >= 3:
        score += 15
        triggers.append(
            "LOGIN_FAILURE"
        )

    elif failed_count >= 1:
        score += 5
        triggers.append(
            "LOGIN_FAILURE"
        )


    # --------------------------------------------------------
    # IP 변경
    # --------------------------------------------------------

    if features["ipChanged"]:
        score += 20
        triggers.append(
            "IP_CHANGED"
        )


    # --------------------------------------------------------
    # User-Agent 변경
    # --------------------------------------------------------

    if features["userAgentChanged"]:
        score += 10
        triggers.append(
            "USER_AGENT_CHANGED"
        )


    # --------------------------------------------------------
    # 신규 기기
    # --------------------------------------------------------

    if features["isNewDevice"]:
        score += 20
        triggers.append(
            "NEW_DEVICE"
        )


    # --------------------------------------------------------
    # 지역 변경
    # --------------------------------------------------------

    if features["regionChanged"]:
        score += 10
        triggers.append(
            "REGION_CHANGED"
        )


    # --------------------------------------------------------
    # Challenge 응답시간
    # --------------------------------------------------------

    response_time = float(
        features["challengeResponseTime"]
    )

    if 0 < response_time < 300:
        score += 10
        triggers.append(
            "ABNORMAL_RESPONSE_TIME"
        )

    elif response_time > 5000:
        score += 5
        triggers.append(
            "ABNORMAL_RESPONSE_TIME"
        )


    # --------------------------------------------------------
    # 새벽 로그인
    # --------------------------------------------------------

    login_hour = int(
        features["loginHour"]
    )

    if 0 <= login_hour <= 5:
        score += 5
        triggers.append(
            "ODD_HOUR"
        )


    score = min(
        score,
        100,
    )


    # --------------------------------------------------------
    # 인증 정책
    # --------------------------------------------------------

    if score <= 30:
        level = "low"
        action = "ACTIVE"

    elif score <= 69:
        level = "medium"
        action = "RE_AUTH"

    else:
        level = "high"
        action = "BLOCKED"


    if not triggers:
        triggers.append(
            "NO_RISK_DETECTED"
        )


    return {
        "rule_score": score,
        "rule_level": level,
        "rule_action": action,
        "rule_triggers": triggers,
    }


# ============================================================
# 정상 시나리오
# ============================================================

def generate_normal_case(
    test_id: int,
) -> dict:

    return {
        "test_id": test_id,
        "scenario_type": "NORMAL",

        "loginFrequency":
            random.randint(1, 4),

        "failedLoginCount":
            random.choices(
                [0, 1],
                weights=[90, 10],
            )[0],

        "ipChanged":
            False,

        "userAgentChanged":
            False,

        "isNewDevice":
            False,

        "regionChanged":
            False,

        "challengeResponseTime":
            random.randint(
                800,
                2500,
            ),

        "loginHour":
            random.randint(
                8,
                22,
            ),

        "dayOfWeek":
            random.randint(
                0,
                6,
            ),

        "expected_action":
            "ACTIVE",
    }


# ============================================================
# 중위험 시나리오
# ============================================================

def generate_medium_case(
    test_id: int,
) -> dict:

    # 중위험이 확실히 나오도록
    # 기본 위험 Feature를 조합한다.

    features = {
        "test_id": test_id,
        "scenario_type": "MEDIUM",

        "loginFrequency":
            random.randint(
                5,
                12,
            ),

        "failedLoginCount":
            random.randint(
                1,
                4,
            ),

        "ipChanged":
            True,

        "userAgentChanged":
            random.choice(
                [False, True]
            ),

        "isNewDevice":
            False,

        "regionChanged":
            random.choice(
                [False, True]
            ),

        "challengeResponseTime":
            random.randint(
                1000,
                3500,
            ),

        "loginHour":
            random.randint(
                7,
                23,
            ),

        "dayOfWeek":
            random.randint(
                0,
                6,
            ),

        "expected_action":
            "RE_AUTH",
    }

    return features


# ============================================================
# 고위험 시나리오
# ============================================================

def generate_high_case(
    test_id: int,
) -> dict:

    return {
        "test_id": test_id,
        "scenario_type": "HIGH",

        "loginFrequency":
            random.randint(
                10,
                20,
            ),

        "failedLoginCount":
            random.randint(
                5,
                10,
            ),

        "ipChanged":
            True,

        "userAgentChanged":
            True,

        "isNewDevice":
            True,

        "regionChanged":
            True,

        "challengeResponseTime":
            random.choice(
                [
                    random.randint(
                        50,
                        250,
                    ),
                    random.randint(
                        5500,
                        9000,
                    ),
                ]
            ),

        "loginHour":
            random.randint(
                0,
                5,
            ),

        "dayOfWeek":
            random.randint(
                0,
                6,
            ),

        "expected_action":
            "BLOCKED",
    }


# ============================================================
# ML 평가
#
# 주의:
# 실제 /analyze에서는 SYNTHETIC 모델 사용 금지.
#
# 이 함수는 회의용 OFFLINE TEST에서만
# SYNTHETIC 모델을 직접 실행한다.
# ============================================================

def evaluate_ml(
    model,
    features: dict,
) -> dict:

    vector = build_feature_vector(
        features
    )

    anomaly_score = float(
        model.score_samples(
            vector
        )[0]
    )

    prediction = int(
        model.predict(
            vector
        )[0]
    )

    return {
        "ml_anomaly_score":
            anomaly_score,

        "ml_prediction":
            prediction,

        "ml_is_anomaly":
            prediction == -1,
    }


# ============================================================
# TEST PASS/FAIL 판단
# ============================================================

def determine_test_result(
    expected_action: str,
    actual_action: str,
) -> str:

    if expected_action == actual_action:
        return "PASS"

    return "FAIL"


# ============================================================
# CSV 저장
# ============================================================

def save_results(
    results: list,
) -> None:

    RESULT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    fieldnames = [
        "test_id",
        "data_source",
        "scenario_type",

        "loginFrequency",
        "failedLoginCount",
        "ipChanged",
        "userAgentChanged",
        "isNewDevice",
        "regionChanged",
        "challengeResponseTime",
        "loginHour",
        "dayOfWeek",

        "rule_score",
        "rule_level",
        "rule_action",
        "rule_triggers",

        "ml_anomaly_score",
        "ml_prediction",
        "ml_is_anomaly",

        "expected_action",
        "actual_action",
        "test_result",
    ]

    with RESULT_FILE.open(
        "w",
        newline="",
        encoding="utf-8-sig",
    ) as csv_file:

        writer = csv.DictWriter(
            csv_file,
            fieldnames=fieldnames,
        )

        writer.writeheader()

        writer.writerows(
            results
        )


# ============================================================
# Summary 출력
# ============================================================

def print_summary(
    results: list,
) -> None:

    total = len(results)

    passed = sum(
        1
        for row in results
        if row["test_result"]
        == "PASS"
    )

    failed = total - passed


    normal_count = sum(
        1
        for row in results
        if row["scenario_type"]
        == "NORMAL"
    )

    medium_count = sum(
        1
        for row in results
        if row["scenario_type"]
        == "MEDIUM"
    )

    high_count = sum(
        1
        for row in results
        if row["scenario_type"]
        == "HIGH"
    )


    anomaly_count = sum(
        1
        for row in results
        if row["ml_is_anomaly"]
    )


    print()
    print("=" * 60)
    print("90건 ML / Risk 통합 테스트 결과")
    print("=" * 60)

    print(
        f"총 테스트: {total}건"
    )

    print(
        f"NORMAL: {normal_count}건"
    )

    print(
        f"MEDIUM: {medium_count}건"
    )

    print(
        f"HIGH: {high_count}건"
    )

    print()

    print(
        f"PASS: {passed}건"
    )

    print(
        f"FAIL: {failed}건"
    )

    print()

    print(
        f"Isolation Forest 이상 판정: "
        f"{anomaly_count}건"
    )

    print()

    print(
        f"CSV 저장 위치:"
    )

    print(
        RESULT_FILE.resolve()
    )

    print("=" * 60)


# ============================================================
# Main
# ============================================================

def main() -> None:

    random.seed(
        RANDOM_SEED
    )


    # --------------------------------------------------------
    # 모델 확인
    # --------------------------------------------------------

    metadata = load_metadata()

    if metadata is None:
        print(
            "[실패] 모델 metadata가 없습니다."
        )
        return


    model = load()

    if model is None:
        print(
            "[실패] Isolation Forest 모델이 없습니다."
        )
        return


    print(
        "테스트에 사용할 모델:"
    )

    print(
        f"model_type="
        f"{metadata.get('model_type')}"
    )

    print(
        f"training_rows="
        f"{metadata.get('training_rows')}"
    )

    print(
        f"feature_count="
        f"{len(FEATURE_ORDER)}"
    )

    print(
        "주의: SYNTHETIC 모델은 "
        "OFFLINE TEST에서만 사용합니다."
    )


    # --------------------------------------------------------
    # 90건 생성
    # --------------------------------------------------------

    scenarios = []

    test_id = 1


    for _ in range(
        NORMAL_COUNT
    ):
        scenarios.append(
            generate_normal_case(
                test_id
            )
        )

        test_id += 1


    for _ in range(
        MEDIUM_COUNT
    ):
        scenarios.append(
            generate_medium_case(
                test_id
            )
        )

        test_id += 1


    for _ in range(
        HIGH_COUNT
    ):
        scenarios.append(
            generate_high_case(
                test_id
            )
        )

        test_id += 1


    # --------------------------------------------------------
    # 평가
    # --------------------------------------------------------

    results = []


    for scenario in scenarios:

        rule_result = (
            calculate_rule_risk(
                scenario
            )
        )

        ml_result = (
            evaluate_ml(
                model,
                scenario,
            )
        )


        actual_action = (
            rule_result[
                "rule_action"
            ]
        )


        test_result = (
            determine_test_result(
                scenario[
                    "expected_action"
                ],
                actual_action,
            )
        )


        result = {
            "test_id":
                scenario["test_id"],

            "data_source":
                "TEST",

            "scenario_type":
                scenario[
                    "scenario_type"
                ],

            "loginFrequency":
                scenario[
                    "loginFrequency"
                ],

            "failedLoginCount":
                scenario[
                    "failedLoginCount"
                ],

            "ipChanged":
                scenario[
                    "ipChanged"
                ],

            "userAgentChanged":
                scenario[
                    "userAgentChanged"
                ],

            "isNewDevice":
                scenario[
                    "isNewDevice"
                ],

            "regionChanged":
                scenario[
                    "regionChanged"
                ],

            "challengeResponseTime":
                scenario[
                    "challengeResponseTime"
                ],

            "loginHour":
                scenario[
                    "loginHour"
                ],

            "dayOfWeek":
                scenario[
                    "dayOfWeek"
                ],

            "rule_score":
                rule_result[
                    "rule_score"
                ],

            "rule_level":
                rule_result[
                    "rule_level"
                ],

            "rule_action":
                rule_result[
                    "rule_action"
                ],

            "rule_triggers":
                "|".join(
                    rule_result[
                        "rule_triggers"
                    ]
                ),

            "ml_anomaly_score":
                ml_result[
                    "ml_anomaly_score"
                ],

            "ml_prediction":
                ml_result[
                    "ml_prediction"
                ],

            "ml_is_anomaly":
                ml_result[
                    "ml_is_anomaly"
                ],

            "expected_action":
                scenario[
                    "expected_action"
                ],

            "actual_action":
                actual_action,

            "test_result":
                test_result,
        }

        results.append(
            result
        )


    # --------------------------------------------------------
    # 정확히 90건인지 검증
    # --------------------------------------------------------

    if len(results) != TOTAL_COUNT:
        raise RuntimeError(
            f"테스트 개수 오류: "
            f"{len(results)}건"
        )


    # --------------------------------------------------------
    # CSV 저장
    # --------------------------------------------------------

    save_results(
        results
    )


    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    print_summary(
        results
    )


if __name__ == "__main__":
    main()