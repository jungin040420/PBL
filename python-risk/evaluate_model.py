from app.isolation_model import (
    FEATURE_ORDER,
    build_feature_vector,
    load,
    load_metadata,
)


def evaluate_case(
    name: str,
    features: dict,
    model,
) -> None:
    """
    오프라인 평가 전용.

    실제 /analyze API와 달리
    SYNTHETIC 모델도 테스트 목적으로 직접 실행한다.
    """

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

    is_anomaly = (
        prediction == -1
    )

    print("=" * 60)
    print(f"테스트: {name}")

    print(
        "Feature Vector:",
        vector.tolist()[0],
    )

    print(
        "Anomaly Score:",
        anomaly_score,
    )

    print(
        "Prediction:",
        prediction,
    )

    print(
        "Is Anomaly:",
        is_anomaly,
    )


def main() -> None:

    # ========================================================
    # 모델 Metadata 확인
    # ========================================================

    metadata = load_metadata()

    if metadata is None:
        print(
            "[실패] 모델 metadata가 없습니다."
        )
        return

    print("=" * 60)
    print("Isolation Forest 오프라인 평가")
    print("=" * 60)

    print(
        "Model Type:",
        metadata.get(
            "model_type"
        ),
    )

    print(
        "Training Rows:",
        metadata.get(
            "training_rows"
        ),
    )

    print(
        "Contamination:",
        metadata.get(
            "contamination"
        ),
    )

    print()

    print(
        "Feature Order:"
    )

    for index, feature in enumerate(
        FEATURE_ORDER,
        start=1,
    ):
        print(
            f"  {index}. {feature}"
        )


    # ========================================================
    # 모델 로드
    # ========================================================

    model = load()

    if model is None:
        print(
            "[실패] Isolation Forest 모델이 없습니다."
        )
        return


    # ========================================================
    # 정상 패턴
    # ========================================================

    normal_case = {

        "loginFrequency": 2,

        "failedLoginCount": 0,

        "ipChanged": False,

        "userAgentChanged": False,

        "isNewDevice": False,

        "regionChanged": False,

        "challengeResponseTime": 1700,

        "loginHour": 14,

        "dayOfWeek": 3,
    }


    # ========================================================
    # 이상 패턴
    # ========================================================

    suspicious_case = {

        "loginFrequency": 18,

        "failedLoginCount": 7,

        "ipChanged": True,

        "userAgentChanged": True,

        "isNewDevice": True,

        "regionChanged": True,

        "challengeResponseTime": 9000,

        "loginHour": 2,

        "dayOfWeek": 6,
    }


    # ========================================================
    # 중간 위험 패턴
    # ========================================================

    medium_case = {

        "loginFrequency": 6,

        "failedLoginCount": 2,

        "ipChanged": True,

        "userAgentChanged": False,

        "isNewDevice": False,

        "regionChanged": False,

        "challengeResponseTime": 2300,

        "loginHour": 20,

        "dayOfWeek": 5,
    }


    # ========================================================
    # 평가 실행
    # ========================================================

    evaluate_case(
        "NORMAL",
        normal_case,
        model,
    )

    evaluate_case(
        "MEDIUM",
        medium_case,
        model,
    )

    evaluate_case(
        "SUSPICIOUS",
        suspicious_case,
        model,
    )


    print("=" * 60)

    print(
        "평가 완료"
    )

    print(
        "주의: SYNTHETIC 모델 결과는 "
        "파이프라인 검증용이며 실제 성능 지표가 아닙니다."
    )

    print(
        "실서비스 /analyze에서는 "
        "REAL 모델만 사용됩니다."
    )


if __name__ == "__main__":
    main()