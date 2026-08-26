import pandas as pd
import numpy as np
import warnings
import os
import joblib
from urllib.parse import urlparse

warnings.filterwarnings('ignore')

from sklearn.model_selection import (
    GroupShuffleSplit,
    GroupKFold,
    cross_val_score
)

from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    f1_score,
    accuracy_score
)

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns


# ─────────────────────────────────────────────
# 0. 설정
# ─────────────────────────────────────────────

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent          # ...\PBL\python-risk

DATA_PATH = BASE_DIR / "data" / "final_dataset_with_all_features_v3_1.csv"
OUTPUT_DIR = BASE_DIR / "output"
os.makedirs(OUTPUT_DIR, exist_ok=True)


RANDOM_STATE = 42

# label: 0=benign, 1=defacement, 2=phishing, 3=malware
# → 0(정상) vs 1,2,3(악성) 이진분류로 재정의한다.

# 학습에서 제외할 컬럼
#   url            : 원본 문자열 (피처 아님)
#   type           : label의 문자열 버전 (leakage)
#   label          : 원본 4-클래스 라벨 (이진 라벨을 새로 만들어서 사용)
#   domain         : 도메인 단위 group split용으로만 사용 (피처 아님)
#   scan_date      : 스캔 시각 타임스탬프 (의미 없는 식별자성 컬럼)
EXCLUDE_COLS = ["url", "type", "label", "domain", "scan_date"]

# 최종적으로 학습에 사용하는 피처 (URL 정적 피처 + web_* 실시간 스캔 피처 + phish_* 휴리스틱 피처)
SELECTED_FEATURES = [
    # ── URL 정적 피처 ──────────────────────────
    "url_len", "@", "?", "-", "=", ".", "#", "%", "+", "$", "!", "*", ",", "//",
    "digits", "letters", "abnormal_url", "https", "Shortining_Service",
    "having_ip_address", "path_underscore_count",

    # ── DOM / 실시간 스캔 피처 (web_*) ───────────
    "web_http_status", "web_is_live", "web_ext_ratio", "web_unique_domains",
    "web_favicon", "web_csp", "web_xframe", "web_hsts", "web_xcontent",
    "web_security_score", "web_forms_count", "web_password_fields",
    "web_hidden_inputs", "web_has_login", "web_ssl_valid",

    # ── 피싱 휴리스틱 피처 (phish_*) ─────────────
    "phish_urgency_words", "phish_security_words", "phish_brand_mentions",
    "phish_brand_hijack", "phish_multiple_subdomains", "phish_long_path",
    "phish_many_params", "phish_suspicious_tld",
    "phish_adv_exact_brand_match", "phish_adv_brand_in_subdomain",
    "phish_adv_brand_in_path", "phish_adv_hyphen_count",
    "phish_adv_number_count", "phish_adv_suspicious_tld",
    "phish_adv_long_domain", "phish_adv_many_subdomains",
    "phish_adv_encoded_chars", "phish_adv_path_keywords",
    "phish_adv_has_redirect", "phish_adv_many_params",

    # ── 경로/기타 ──────────────────────────────
    "path_has_hacked_terms", "suspicious_extension", "is_gov_edu",
]


# ─────────────────────────────────────────────
# 1. 데이터 로드
# ─────────────────────────────────────────────

def load_data(path: str) -> pd.DataFrame:
    print(f"[1/5] 데이터 로드 중: {path}")

    df = pd.read_csv(path)

    print(f"  → 원본 shape: {df.shape}")

    print("  → 원본 label(4-class) 분포:")
    print(df["label"].value_counts())

    # ★ 이진 라벨 재정의: 0(benign) → 0, 1/2/3(defacement/phishing/malware) → 1
    df["label"] = (df["label"] != 0).astype(int)

    print("  → 이진 변환 후 label 분포 (0=정상, 1=악성):")
    print(df["label"].value_counts())

    # domain 결측치 처리: group split 기준이므로, 없으면 url 자체를 그룹으로 사용
    before = df["domain"].isnull().sum()
    if before > 0:
        print(f"  → domain 결측 {before}건 → url로 대체 (단일 그룹 처리)")
        df["domain"] = df["domain"].fillna(df["url"])

    print(f"  → 고유 도메인 수: {df['domain'].nunique()}")

    return df


# ─────────────────────────────────────────────
# 2. 피처 선택
# ─────────────────────────────────────────────

def select_features(df: pd.DataFrame) -> pd.DataFrame:
    print("\n[2/5] 피처 선택")

    cols = SELECTED_FEATURES + ["label", "domain"]
    df = df[cols].copy()

    print(f"  → 선택된 피처 수: {len(SELECTED_FEATURES)}")

    return df


# ─────────────────────────────────────────────
# 3. 전처리
# ─────────────────────────────────────────────

def preprocess(df: pd.DataFrame):

    print("\n[3/5] 전처리")

    # 결측치 처리
    if df.isnull().sum().sum() > 0:
        print("  [결측치] 처리 중...")

        for col in df.columns:
            if df[col].isnull().sum() == 0:
                continue

            if df[col].dtype == object:
                df[col] = df[col].fillna(df[col].mode()[0])
            else:
                df[col] = df[col].fillna(df[col].median())
    else:
        print("  [결측치] 없음 ✓")

    # 그룹 저장 (도메인 단위로 train/test가 섞이지 않도록)
    groups = df["domain"]

    # X / y 분리
    X = df.drop(columns=["label", "domain"])
    y = df["label"]

    # 이진(0/1) 컬럼은 스케일링/로그변환에서 제외 (동적으로 판별)
    binary_cols = [c for c in X.columns if X[c].nunique() <= 2]
    numeric_cols = [c for c in X.columns if c not in binary_cols]

    print(f"  → 이진 피처 {len(binary_cols)}개 / 수치 피처 {len(numeric_cols)}개")

    # 로그 변환: 왜도(skew)가 큰(우측 편향) 수치 컬럼에만 log1p 적용
    # (예측 시점에도 동일하게 재현해야 하므로 컬럼 목록을 저장해둔다)
    log_cols = []
    for col in numeric_cols:
        if (X[col] >= 0).all() and X[col].skew() > 1.0:
            X[col] = np.log1p(X[col])
            log_cols.append(col)

    print(f"  [로그변환] log1p 적용 컬럼 {len(log_cols)}개: {log_cols}")

    # 이상치 clipping (수치 컬럼만, 99.5% 지점 기준)
    # → 예측 시점에도 동일한 상한값으로 clip해야 하므로 값 자체를 저장해둔다
    print("  [이상치] 99.5% clipping")

    clip_upper = {}
    for col in numeric_cols:
        upper = X[col].quantile(0.995)
        X[col] = X[col].clip(upper=upper)
        clip_upper[col] = upper

    print(f"  → X shape: {X.shape}")

    return X, y, groups, binary_cols, numeric_cols, log_cols, clip_upper


# ─────────────────────────────────────────────
# 4. 학습 / 평가
# ─────────────────────────────────────────────

def train_and_evaluate(X, y, groups, binary_cols, numeric_cols):

    print("\n[4/5] 학습 및 평가")

    # Group-based split
    print("  [분할] GroupShuffleSplit")

    gss = GroupShuffleSplit(
        n_splits=1,
        test_size=0.2,
        random_state=RANDOM_STATE
    )

    train_idx, test_idx = next(gss.split(X, y, groups=groups))

    X_train = X.iloc[train_idx]
    X_test = X.iloc[test_idx]

    y_train = y.iloc[train_idx]
    y_test = y.iloc[test_idx]

    group_train = groups.iloc[train_idx]

    print(f"  Train: {len(X_train)}")
    print(f"  Test : {len(X_test)}")
    print(f"  Train domains: {group_train.nunique()}")
    print(f"  Test domains : {groups.iloc[test_idx].nunique()}")

    # 스케일링 (이진 컬럼 제외, 수치 컬럼만)
    scale_cols = numeric_cols

    scaler = StandardScaler()

    X_train_sc = X_train.copy()
    X_test_sc = X_test.copy()

    X_train_sc[scale_cols] = scaler.fit_transform(X_train[scale_cols])
    X_test_sc[scale_cols] = scaler.transform(X_test[scale_cols])

    # 모델
    models = {
        "Logistic Regression": LogisticRegression(
            max_iter=1000,
            random_state=RANDOM_STATE,
            class_weight="balanced"
        ),

        "Random Forest": RandomForestClassifier(
            n_estimators=200,
            random_state=RANDOM_STATE,
            class_weight="balanced",
            n_jobs=-1
        ),

        "Gradient Boosting": GradientBoostingClassifier(
            n_estimators=200,
            learning_rate=0.1,
            max_depth=5,
            random_state=RANDOM_STATE
        )
    }

    results = {}

    for name, model in models.items():

        print(f"\n▶ {name}")

        cv = GroupKFold(n_splits=5)

        cv_auc = cross_val_score(
            model,
            X_train_sc,
            y_train,
            cv=cv,
            groups=group_train,
            scoring="roc_auc",
            n_jobs=-1
        )

        print(f"  Group CV ROC-AUC: {cv_auc.mean():.4f} ± {cv_auc.std():.4f}")

        model.fit(X_train_sc, y_train)

        y_pred = model.predict(X_test_sc)
        y_prob = model.predict_proba(X_test_sc)[:, 1]

        acc = accuracy_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred, average="weighted")
        auc = roc_auc_score(y_test, y_prob)

        print(f"  Accuracy : {acc:.4f}")
        print(f"  F1 Score : {f1:.4f}")
        print(f"  ROC-AUC  : {auc:.4f}")

        print(
            classification_report(
                y_test,
                y_pred,
                target_names=["Legitimate", "Malicious"]
            )
        )

        results[name] = {
            "model": model,
            "y_pred": y_pred,
            "y_prob": y_prob,
            "acc": acc,
            "f1": f1,
            "auc": auc,
            "cv_auc_mean": cv_auc.mean(),
            "cv_auc_std": cv_auc.std(),
        }

    return results, X_test, y_test, X_train, scaler, scale_cols


# ─────────────────────────────────────────────
# 5. 시각화
# ─────────────────────────────────────────────

def visualize(results, X_train):

    print("\n[5/5] 시각화 저장 중...")

    rf_model = results["Random Forest"]["model"]

    importances = pd.Series(
        rf_model.feature_importances_,
        index=X_train.columns
    )

    importances = importances.sort_values(ascending=True).tail(25)

    plt.figure(figsize=(10, 9))
    importances.plot(kind="barh", color="skyblue")
    plt.title("Feature Importance (Random Forest)")
    plt.xlabel("Importance")
    plt.tight_layout()

    out_path = os.path.join(OUTPUT_DIR, "feature_importance.png")
    plt.savefig(out_path)

    print(f"  → 저장 완료: {out_path}")


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

if __name__ == "__main__":

    print("=" * 55)
    print("Malicious URL Detection - Domain-aware ML Pipeline")
    print("(URL Feature + DOM/Web Scan Feature + Phishing Heuristic Feature)")
    print("=" * 55)

    df = load_data(DATA_PATH)
    df = select_features(df)

    X, y, groups, binary_cols, numeric_cols, log_cols, clip_upper = preprocess(df)

    results, X_test, y_test, X_train, scaler, scale_cols = train_and_evaluate(
        X, y, groups, binary_cols, numeric_cols
    )

    visualize(results, X_train)

    print("\n" + "=" * 55)
    print("최종 요약")
    print("=" * 55)

    best_name = max(results, key=lambda x: results[x]["auc"])
    best = results[best_name]

    print(f"최고 모델 : {best_name}")
    print(f"Accuracy : {best['acc']:.4f}")
    print(f"F1 Score : {best['f1']:.4f}")
    print(f"ROC-AUC  : {best['auc']:.4f}")
    print("=" * 55)

    # 모델 저장
    os.makedirs("output", exist_ok=True)

    joblib.dump(
        results["Random Forest"]["model"],
        os.path.join(OUTPUT_DIR, "rf_model.pkl")
    )

    joblib.dump(
        scaler,
        os.path.join(OUTPUT_DIR, "scaler.pkl")
    )

    joblib.dump(
        scale_cols,
        os.path.join(OUTPUT_DIR, "scale_cols.pkl")
    )

    joblib.dump(
        SELECTED_FEATURES,
        os.path.join(OUTPUT_DIR, "selected_features.pkl")
    )

    joblib.dump(
        log_cols,
        os.path.join(OUTPUT_DIR, "log_cols.pkl")
    )


    joblib.dump(
        clip_upper,
        os.path.join(OUTPUT_DIR, "clip_upper.pkl")
    )

    print(f"✅ 모델/전처리 객체 저장 완료 → {OUTPUT_DIR}/")