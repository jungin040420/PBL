# Adaptive Multi-Layer MFA (FIDO2/Passkey)

AiTM(Adversary-in-The-Middle) 세션 탈취 공격에 대응하기 위한 **FIDO2/Passkey 기반 적응형 다계층 인증 시스템**입니다. URL 검증, FIDO2 인증, 리스크 스코어링 3계층으로 구성되며, 접속 환경의 위험도에 따라 인증 강도를 동적으로 조정합니다.

> 2026년 한이음 드림업 프로젝트 | 2026.04 ~ 2026.10

## 배경

전통적인 MFA는 인증 완료 이후의 세션 탈취를 탐지하지 못합니다. 본 시스템은 FIDO2의 도메인 바인딩된 서명키 구조로 로그인 단계의 자격증명 탈취(피싱, 크리덴셜 스터핑)를 원천 차단하고, 인증 이후의 세션 탈취 시도는 리스크 스코어링 기반 적응형 인증으로 대응합니다.

## 시스템 구조

```
사용자 접속
   │
   ▼
[1] AI 피싱 URL 탐지 ──── 피싱 감지 → 즉시 차단
   │ 정상
   ▼
[2] FIDO2/Passkey 생체 인증
   │
   ▼
[3] 리스크 스코어링 (Rule-Based + Isolation Forest)
   │
   ├─ 0~30점   → ACTIVE (정상 통과)
   ├─ 31~69점  → RE_AUTH (이메일 OTP / Passkey Step-up 재인증)
   └─ 70점 이상 → BLOCKED (세션 차단)
```

| 레이어 | 기술 스택 |
|---|---|
| 클라이언트 | WebAuthn API, 생체 인식 센서 |
| API/보안 게이트웨이 | Nginx, Let's Encrypt SSL |
| 인증 서버 (RP) | Node.js/Express, @simplewebauthn/server |
| 리스크·ML 서버 | Python/FastAPI, Scikit-learn (Isolation Forest, Random Forest) |
| 데이터 | MySQL 8.0 (`mfa_db`, `authdb`, `ml_db`), Redis 7.2 |
| 모니터링 | Elasticsearch, Kibana |
| 인프라 | Docker Compose, AWS EC2, GitHub Actions CI/CD |

## 주요 기능

- **FIDO2/Passkey 인증**: 비밀번호 없는 공개키 기반 인증, Challenge 생성 및 서명 검증
- **AI 피싱 URL 탐지**: Random Forest 기반 URL 패턴 분석, Playwright 기반 동적 렌더링 수집
- **리스크 스코어링**: B(행동)·N(네트워크)·D(기기)·T(위협이력)·C(컨텍스트) 5개 영역 기반 하이브리드 점수 산출
  - Rule-Based 고정 가중치를 기준선으로 두고, Isolation Forest 이상 탐지 결과를 가산점으로 결합
  - ML은 보조 신호로만 사용하여 장애 시 Rule-Based만으로 동작하는 대체(fallback) 구조 유지
- **적응형 재인증**: 이메일 OTP, 민감 작업에 대한 Passkey Step-up 재인증
- **세션 관리**: Redis 기반 슬라이딩 TTL + 절대 만료, AiTM 세션 하이재킹 탐지(IP+User-Agent 해시 바인딩)
- **개인정보 보호**: SHA-256+Salt 해싱 기반 비식별화(용도별 salt 분리), 감사 로그 AES-256-GCM 암호화, TTL 기반 자동 파기

## 팀 구성

| Part | 담당 영역 |
|---|---|
| Part 1 | FIDO2 RP 서버, WebAuthn 코어 로직, 세션 관리 |
| Part 2 | AI/ML 피싱 URL 탐지 |
| Part 3 | 리스크 스코어링 엔진 |
| Part 4 | 개인정보 보호 및 컴플라이언스 |
| Part 5 | 보안 모니터링, ELK 스택, 대시보드 |

## 학술적 기반

리스크 스코어링 모델은 Jeong & Yang (2025, *Applied Sciences*, SCIE)의 Trust Score 4요소(B/N/D/T) 가중합 구조를 채택하되, 네트워크 침입탐지 환경이 아닌 FIDO2 인증 도메인에 맞게 메트릭을 재설계하였습니다.

```
TS = W_B·B + W_N·N + W_D·D + W_T·T + W_C·C
```

## 개발 환경

```
Node.js / Express        Python / FastAPI
@simplewebauthn/server   Scikit-learn
MySQL 8.0                Redis 7.2
Docker Compose           AWS EC2 (Amazon Linux 2023)
Nginx + Let's Encrypt    GitHub Actions
```

## 라이선스

이 프로젝트는 2026년 한이음 드림업 프로젝트의 결과물로, 과학기술정보통신부·정보통신기획평가원(IITP)의 지원을 받아 수행되었습니다.
