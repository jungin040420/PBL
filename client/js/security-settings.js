const changeAuthButton =
    document.getElementById("changeAuthButton");

const analysis =
    document.getElementById("analysis");

const riskScore =
    document.getElementById("riskScore");

const riskLevel =
    document.getElementById("riskLevel");

const mlModel =
    document.getElementById("mlModel");

const mlScore =
    document.getElementById("mlScore");

const decision =
    document.getElementById("decision");

const reauthArea =
    document.getElementById("reauthArea");

const riskMessage =
    document.getElementById("riskMessage");

const errorMessage =
    document.getElementById("errorMessage");

const reauthButton =
    document.getElementById("reauthButton");


// ============================================================
// Base64URL -> ArrayBuffer
// ============================================================

function base64UrlToArrayBuffer(value) {
    const base64 = value
        .replace(/-/g, "+")
        .replace(/_/g, "/");

    const padded =
        base64 +
        "=".repeat(
            (4 - (base64.length % 4)) % 4
        );

    const binary =
        window.atob(padded);

    const bytes =
        new Uint8Array(binary.length);

    for (
        let i = 0;
        i < binary.length;
        i += 1
    ) {
        bytes[i] =
            binary.charCodeAt(i);
    }

    return bytes.buffer;
}


// ============================================================
// ArrayBuffer -> Base64URL
// ============================================================

function arrayBufferToBase64Url(buffer) {
    const bytes =
        new Uint8Array(buffer);

    let binary = "";

    for (const byte of bytes) {
        binary +=
            String.fromCharCode(byte);
    }

    return window
        .btoa(binary)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/g, "");
}


// ============================================================
// WebAuthn PublicKey 옵션 추출
// ============================================================

function extractPublicKeyOptions(data) {
    return (
        data.options?.publicKey ??
        data.options ??
        data.publicKey ??
        data
    );
}


// ============================================================
// 성공 UI
// ============================================================

function showStepUpSuccess() {
    let successBox =
        document.getElementById(
            "stepUpSuccess"
        );

    if (!successBox) {
        successBox =
            document.createElement("div");

        successBox.id =
            "stepUpSuccess";

        successBox.style.marginTop =
            "24px";

        successBox.style.padding =
            "20px";

        successBox.style.borderRadius =
            "8px";

        successBox.style.background =
            "#ecfdf5";

        successBox.style.border =
            "1px solid #10b981";

        reauthArea.insertAdjacentElement(
            "afterend",
            successBox
        );
    }

    successBox.innerHTML = `
    <h3 style="margin-top:0;color:#047857;">
      ✓ RE-AUTHENTICATION SUCCESS
    </h3>

    <p>
      Passkey를 통해 사용자의 신원이 다시 확인되었습니다.
    </p>

    <p>
      <strong>
        민감 행위 수행 권한이 허용되었습니다.
      </strong>
    </p>

    <div style="
        margin-top:16px;
        padding:12px;
        border-radius:6px;
        background:white;
    ">
      Sensitive Action:
      <strong>AUTH_METHOD_CHANGE</strong>
      <br>

      Access:
      <strong style="color:#047857;">
        GRANTED
      </strong>
    </div>
  `;
}


// ============================================================
// CASE 3 - 민감행위 Risk Re-Evaluation
// ============================================================

async function requestSensitiveAction() {
    errorMessage.textContent = "";

    analysis.style.display =
        "block";

    reauthArea.style.display =
        "none";

    changeAuthButton.disabled =
        true;

    changeAuthButton.textContent =
        "Risk 재평가 중...";

    try {
        const response =
            await fetch(
                "/api/sensitive/auth-method-change",
                {
                    method: "POST",

                    credentials:
                        "include",

                    headers: {
                        "Content-Type":
                            "application/json"
                    }
                }
            );

        const data =
            await response.json();

        console.log(
            "[CASE3] Risk Re-Evaluation",
            data
        );

        if (!response.ok) {
            throw new Error(
                data.message ||
                data.error ||
                `HTTP ${response.status}`
            );
        }

        riskScore.textContent =
            data.riskScore ?? "-";

        riskLevel.textContent =
            data.riskLevel ?? "-";

        decision.textContent =
            data.finalAction ??
            data.baseRiskAction ??
            "-";

        mlModel.textContent =
            data.ml?.modelType ??
            "-";

        mlScore.textContent =
            data.ml?.anomalyScore ??
            "-";

        if (
            data.finalAction ===
            "RE_AUTH" ||
            data.requiresReauthentication
        ) {
            reauthArea.style.display =
                "block";

            riskMessage.textContent =
                "민감 행위를 계속하려면 Passkey 추가 인증이 필요합니다.";
        }

    } catch (error) {
        console.error(
            "[CASE3] Risk error:",
            error
        );

        errorMessage.textContent =
            `오류: ${error.message}`;

    } finally {
        changeAuthButton.disabled =
            false;

        changeAuthButton.textContent =
            "인증수단 변경";
    }
}


// ============================================================
// CASE 3 - Passkey Step-up Authentication
// ============================================================

async function performStepUpAuthentication() {
    errorMessage.textContent = "";

    reauthButton.disabled =
        true;

    reauthButton.textContent =
        "Passkey 인증 중...";

    try {

        // --------------------------------------------------------
        // 1. 현재 로그인 사용자 확인
        // --------------------------------------------------------

        const meResponse =
            await fetch(
                "/api/sensitive/reauth-context",
                {
                    method: "GET",
                    credentials: "include"
                }
            );

        const meData =
            await meResponse.json();

        if (!meResponse.ok) {
            throw new Error(
                meData.error ||
                "현재 로그인 세션을 확인할 수 없습니다."
            );
        }

        const username =
            meData.username;

        if (!username) {
            throw new Error(
                "로그인 사용자 정보를 확인할 수 없습니다."
            );
        }

        console.log(
            "[CASE3][STEP_UP] username:",
            username
        );


        // --------------------------------------------------------
        // 2. 새 Passkey Challenge 발급
        // --------------------------------------------------------

        const startResponse =
            await fetch(
                "/auth/login/start",
                {
                    method: "POST",

                    credentials:
                        "include",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({
                        username
                    })
                }
            );

        const startData =
            await startResponse.json();

        if (!startResponse.ok) {
            throw new Error(
                startData.error ||
                "Step-up Challenge 발급 실패"
            );
        }

        const publicKeyOptions =
            extractPublicKeyOptions(
                startData
            );

        const challengeId =
            startData.challengeId ??
            startData.options?.challengeId ??
            startData.publicKey?.challengeId ??
            publicKeyOptions.challengeId;

        if (
            !publicKeyOptions.challenge ||
            !challengeId
        ) {
            throw new Error(
                "Step-up Challenge 정보가 올바르지 않습니다."
            );
        }


        // --------------------------------------------------------
        // 3. WebAuthn 데이터 변환
        // --------------------------------------------------------

        publicKeyOptions.challenge =
            base64UrlToArrayBuffer(
                publicKeyOptions.challenge
            );

        if (
            Array.isArray(
                publicKeyOptions.allowCredentials
            )
        ) {
            publicKeyOptions.allowCredentials =
                publicKeyOptions
                    .allowCredentials
                    .map(
                        credential => ({
                            ...credential,

                            id:
                                base64UrlToArrayBuffer(
                                    credential.id
                                ),

                            type:
                                credential.type ||
                                "public-key"
                        })
                    );
        }


        // --------------------------------------------------------
        // 4. 실제 Passkey Step-up 인증
        // --------------------------------------------------------

        const assertion =
            await navigator
                .credentials
                .get({
                    publicKey:
                    publicKeyOptions
                });

        if (!assertion) {
            throw new Error(
                "Passkey 인증 결과가 없습니다."
            );
        }


        // --------------------------------------------------------
        // 5. Credential 직렬화
        // --------------------------------------------------------

        const credential = {
            id:
            assertion.id,

            rawId:
                arrayBufferToBase64Url(
                    assertion.rawId
                ),

            type:
            assertion.type,

            response: {
                authenticatorData:
                    arrayBufferToBase64Url(
                        assertion
                            .response
                            .authenticatorData
                    ),

                clientDataJSON:
                    arrayBufferToBase64Url(
                        assertion
                            .response
                            .clientDataJSON
                    ),

                signature:
                    arrayBufferToBase64Url(
                        assertion
                            .response
                            .signature
                    ),

                userHandle:
                    assertion.response.userHandle
                        ? arrayBufferToBase64Url(
                            assertion
                                .response
                                .userHandle
                        )
                        : null
            },

            clientExtensionResults:
                assertion
                    .getClientExtensionResults()
        };


        // --------------------------------------------------------
        // 6. 서버에서 Passkey 검증
        // --------------------------------------------------------

        const finishResponse =
            await fetch(
                "/auth/login/finish",
                {
                    method:
                        "POST",

                    credentials:
                        "include",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body:
                        JSON.stringify({
                            username,
                            challengeId,
                            credential
                        })
                }
            );

        const finishData =
            await finishResponse.json();

        console.log(
            "[CASE3][STEP_UP] result:",
            finishData
        );


        if (!finishResponse.ok) {
            throw new Error(
                finishData.error ||
                finishData.message ||
                "Passkey 추가 인증 실패"
            );
        }


        if (
            finishData.riskAction ===
            "BLOCKED"
        ) {
            throw new Error(
                "재인증 과정에서 고위험 상태가 탐지되어 차단되었습니다."
            );
        }


        if (
            finishData.success !== true
        ) {
            throw new Error(
                finishData.message ||
                "추가 인증에 실패했습니다."
            );
        }


        // --------------------------------------------------------
        // 7. Step-up 성공
        // --------------------------------------------------------

        reauthButton.textContent =
            "재인증 성공 ✓";

        reauthButton.disabled =
            true;

        decision.textContent =
            "RE_AUTH → GRANTED";

        decision.style.color =
            "#047857";

        showStepUpSuccess();

        console.log(
            "[CASE3][STEP_UP_AUTH_SUCCESS]",
            {
                username,
                sensitiveAction:
                    "AUTH_METHOD_CHANGE"
            }
        );

    } catch (error) {

        console.error(
            "[CASE3][STEP_UP_ERROR]",
            error
        );

        errorMessage.textContent =
            `추가 인증 오류: ${error.message}`;

        reauthButton.disabled =
            false;

        reauthButton.textContent =
            "Passkey로 추가 인증";
    }
}


// ============================================================
// Event
// ============================================================

changeAuthButton.addEventListener(
    "click",
    requestSensitiveAction
);

reauthButton.addEventListener(
    "click",
    performStepUpAuthentication
);