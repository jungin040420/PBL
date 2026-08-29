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
// Step-up 성공 UI
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
// CASE 3
// 민감 행위 Risk Re-Evaluation
// ============================================================

async function requestSensitiveAction() {
  errorMessage.textContent =
      "";

  analysis.style.display =
      "block";

  reauthArea.style.display =
      "none";

  changeAuthButton.disabled =
      true;

  changeAuthButton.textContent =
      "Risk 재평가 중...";

  try {

    // --------------------------------------------------------
    // 1. 현재 Context 재수집 + Session 검증 + Risk 분석
    // --------------------------------------------------------

    const response =
        await fetch(
            "/api/sensitive/auth-method-change",
            {
              method:
                  "POST",

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
        "[CASE3][RISK_RE_EVALUATION]",
        data
    );


    if (!response.ok) {
      throw new Error(
          data.message ||
          data.error ||
          `HTTP ${response.status}`
      );
    }


    // --------------------------------------------------------
    // 2. Risk 결과 UI 반영
    // --------------------------------------------------------

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


    // --------------------------------------------------------
    // 3. RE_AUTH이면 Passkey Step-up UI 표시
    // --------------------------------------------------------

    if (
        data.finalAction ===
        "RE_AUTH" ||
        data.requiresReauthentication
    ) {

      reauthArea.style.display =
          "block";

      riskMessage.textContent =
          "민감 행위를 계속하려면 Passkey 추가 인증이 필요합니다.";

      reauthButton.disabled =
          false;

      reauthButton.textContent =
          "Passkey로 추가 인증";

      return;
    }


    // --------------------------------------------------------
    // 4. BLOCKED
    // --------------------------------------------------------

    if (
        data.finalAction ===
        "BLOCKED"
    ) {

      throw new Error(
          data.message ||
          "고위험 상태가 탐지되어 민감 행위가 차단되었습니다."
      );
    }


  } catch (error) {

    console.error(
        "[CASE3][RISK_ERROR]",
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
// CASE 3
// Passkey Step-up Authentication
//
// 핵심:
// /auth/login/finish 사용 안 함
// /api/sensitive/stepup/complete 사용 안 함
//
// 전용 API:
// /api/sensitive/stepup/verify
//
// 에서
// 1. 기존 RE_AUTH 세션 확인
// 2. stepup:{userId}=PENDING 확인
// 3. Passkey 검증
// 4. 같은 세션 ACTIVE 복구
// 5. stepup key 삭제
// 를 한 번에 처리한다.
// ============================================================

async function performStepUpAuthentication() {
  errorMessage.textContent =
      "";

  reauthButton.disabled =
      true;

  reauthButton.textContent =
      "Passkey 인증 중...";

  try {

    // --------------------------------------------------------
    // 1. 현재 RE_AUTH Session / Step-up Context 확인
    // --------------------------------------------------------

    const contextResponse =
        await fetch(
            "/api/sensitive/reauth-context",
            {
              method:
                  "GET",

              credentials:
                  "include"
            }
        );


    const contextData =
        await contextResponse.json();


    if (!contextResponse.ok) {

      throw new Error(
          contextData.error ||
          contextData.message ||
          "현재 Step-up 세션을 확인할 수 없습니다."
      );
    }


    const username =
        contextData.username;


    if (!username) {

      throw new Error(
          "로그인 사용자 정보를 확인할 수 없습니다."
      );
    }


    console.log(
        "[CASE3][STEP_UP_CONTEXT]",
        {
          userId:
          contextData.userId,

          username,

          sessionId:
          contextData.sessionId,

          stepupState:
          contextData.stepupState,

          remainingTTL:
          contextData.remainingTTL
        }
    );


    // --------------------------------------------------------
    // 2. Passkey Challenge 발급
    //
    // Challenge 생성만 기존 login/start를 재사용한다.
    // 이 API는 새 로그인 세션을 생성하지 않는다.
    // --------------------------------------------------------

    const startResponse =
        await fetch(
            "/auth/login/start",
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
                    username
                  })
            }
        );


    const startData =
        await startResponse.json();


    if (!startResponse.ok) {

      throw new Error(
          startData.error ||
          startData.message ||
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
                  item => ({
                    ...item,

                    id:
                        base64UrlToArrayBuffer(
                            item.id
                        ),

                    type:
                        item.type ||
                        "public-key"
                  })
              );
    }


    // --------------------------------------------------------
    // 4. 브라우저 Passkey 인증
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
    // 6. CASE3 전용 Passkey Step-up 검증
    //
    // 절대 /auth/login/finish 호출하지 않는다.
    //
    // Backend:
    //
    // 기존 Session(RE_AUTH)
    //      ↓
    // stepup:{userId}=PENDING
    //      ↓
    // verificationService.verifyLogin()
    //      ↓
    // Passkey Verified
    //      ↓
    // 기존 Session ACTIVE
    //      ↓
    // DEL stepup:{userId}
    //      ↓
    // GRANTED
    // --------------------------------------------------------

    const verifyResponse =
        await fetch(
            "/api/sensitive/stepup/verify",
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
                    challengeId,
                    credential
                  })
            }
        );


    const verifyData =
        await verifyResponse.json();


    console.log(
        "[CASE3][STEP_UP_VERIFY]",
        verifyData
    );


    if (!verifyResponse.ok) {

      throw new Error(
          verifyData.error ||
          verifyData.message ||
          "Passkey Step-up 인증 실패"
      );
    }


    // --------------------------------------------------------
    // 7. 백엔드 성공 응답 검증
    // --------------------------------------------------------

    if (
        verifyData.success !== true
    ) {

      throw new Error(
          verifyData.error ||
          verifyData.message ||
          "Passkey Step-up 인증에 실패했습니다."
      );
    }


    if (
        verifyData.access !==
        "GRANTED"
    ) {

      throw new Error(
          "민감 행위 수행 권한이 승인되지 않았습니다."
      );
    }


    if (
        verifyData.sessionStatus !==
        "ACTIVE"
    ) {

      throw new Error(
          "Passkey Step-up 후 세션 상태가 ACTIVE가 아닙니다."
      );
    }


    if (
        verifyData.reauthenticationMethod !==
        "PASSKEY"
    ) {

      throw new Error(
          "재인증 방식 검증에 실패했습니다."
      );
    }


    // --------------------------------------------------------
    // 8. 백엔드 검증 완료 후에만 성공 UI 표시
    // --------------------------------------------------------

    reauthButton.textContent =
        "재인증 성공 ✓";

    reauthButton.disabled =
        true;


    decision.textContent =
        "RE_AUTH → GRANTED";

    decision.style.color =
        "#047857";


    riskMessage.textContent =
        "Passkey 추가 인증이 완료되어 민감 행위 수행 권한이 허용되었습니다.";


    showStepUpSuccess();


    console.log(
        "[CASE3][STEP_UP_AUTH_SUCCESS]",
        {
          username,

          sensitiveAction:
          verifyData.sensitiveAction,

          reauthenticationMethod:
          verifyData.reauthenticationMethod,

          sessionStatus:
          verifyData.sessionStatus,

          access:
          verifyData.access
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