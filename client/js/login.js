function setStatus(message) {
  const statusElement = document.getElementById("status");

  if (statusElement) {
    statusElement.textContent = message;
  }
}


/**
 * Base64URL 문자열을 ArrayBuffer로 변환
 */
function base64UrlToArrayBuffer(value, fieldName = "Base64URL 값") {
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`${fieldName}이 없거나 올바르지 않습니다.`);
  }

  const base64 = value
      .replace(/-/g, "+")
      .replace(/_/g, "/");

  const paddedBase64 =
      base64 + "=".repeat((4 - (base64.length % 4)) % 4);

  const binary = window.atob(paddedBase64);
  const bytes = new Uint8Array(binary.length);

  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }

  return bytes.buffer;
}


/**
 * ArrayBuffer를 Base64URL 문자열로 변환
 */
function arrayBufferToBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return window
      .btoa(binary)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/g, "");
}


/**
 * 서버 응답이 options로 감싸진 경우와
 * 바로 WebAuthn 옵션을 반환하는 경우를 모두 처리
 */
function extractPublicKeyOptions(responseData) {
  if (!responseData || typeof responseData !== "object") {
    throw new Error("로그인 시작 응답이 올바르지 않습니다.");
  }

  if (responseData.error) {
    throw new Error(responseData.error);
  }

  return (
      responseData.options?.publicKey ??
      responseData.options ??
      responseData.publicKey ??
      responseData
  );
}


/**
 * Passkey 로그인
 */
async function startPasskeyLogin() {
  try {
    const usernameInput =
        document.getElementById("username");

    const username =
        usernameInput?.value?.trim();

    if (!username) {
      setStatus("사용자 아이디를 입력해주세요.");
      return;
    }

    if (!window.PublicKeyCredential) {
      throw new Error(
          "이 브라우저는 Passkey/WebAuthn을 지원하지 않습니다."
      );
    }

    setStatus("로그인 요청 중...");

    /*
     * 1. 로그인 Challenge 요청
     */
    const startResponse = await fetch(
        "/auth/login/start",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            username,
          }),
        }
    );

    let startData;

    try {
      startData = await startResponse.json();
    } catch {
      throw new Error(
          `로그인 시작 응답을 읽을 수 없습니다. HTTP ${startResponse.status}`
      );
    }

    console.log(
        "로그인 시작 응답:",
        startData
    );

    /*
     * 429, 400, 500 등의 오류 응답을
     * Passkey 옵션으로 처리하지 않도록 먼저 중단
     */
    if (!startResponse.ok) {
      throw new Error(
          startData.error ||
          `로그인 시작 실패 (HTTP ${startResponse.status})`
      );
    }

    const publicKeyOptions =
        extractPublicKeyOptions(startData);

    if (!publicKeyOptions.challenge) {
      console.error(
          "challenge 누락 응답:",
          startData
      );

      throw new Error(
          "서버 응답에 challenge가 없습니다."
      );
    }

    /*
     * 2. WebAuthn용 바이너리 변환
     */
    publicKeyOptions.challenge =
        base64UrlToArrayBuffer(
            publicKeyOptions.challenge,
            "challenge"
        );

    if (
        Array.isArray(
            publicKeyOptions.allowCredentials
        )
    ) {
      publicKeyOptions.allowCredentials =
          publicKeyOptions.allowCredentials.map(
              (credential, index) => {
                if (!credential?.id) {
                  throw new Error(
                      `allowCredentials[${index}].id가 없습니다.`
                  );
                }

                return {
                  ...credential,
                  id: base64UrlToArrayBuffer(
                      credential.id,
                      `allowCredentials[${index}].id`
                  ),
                  type:
                      credential.type ||
                      "public-key",
                };
              }
          );
    }

    setStatus(
        "Passkey 인증을 진행해주세요..."
    );

    /*
     * 3. 브라우저 Passkey 인증
     */
    const assertion =
        await navigator.credentials.get({
          publicKey: publicKeyOptions,
        });

    if (!assertion) {
      throw new Error(
          "Passkey 인증 결과를 받지 못했습니다."
      );
    }

    /*
     * challengeId 위치가 서버 구현마다 다를 수 있어
     * 여러 형태를 대응
     */
    const challengeId =
        startData.challengeId ??
        startData.options?.challengeId ??
        startData.publicKey?.challengeId ??
        publicKeyOptions.challengeId;

    if (!challengeId) {
      console.error(
          "challengeId 누락 응답:",
          startData
      );

      throw new Error(
          "서버 응답에 challengeId가 없습니다."
      );
    }

    /*
     * 4. Credential 직렬화
     */
    const credential = {
      id: assertion.id,
      rawId: arrayBufferToBase64Url(
          assertion.rawId
      ),
      type: assertion.type,

      response: {
        authenticatorData:
            arrayBufferToBase64Url(
                assertion.response
                    .authenticatorData
            ),

        clientDataJSON:
            arrayBufferToBase64Url(
                assertion.response
                    .clientDataJSON
            ),

        signature:
            arrayBufferToBase64Url(
                assertion.response.signature
            ),

        userHandle:
            assertion.response.userHandle
                ? arrayBufferToBase64Url(
                    assertion.response
                        .userHandle
                )
                : null,
      },

      clientExtensionResults:
          assertion.getClientExtensionResults(),
    };

    setStatus(
        "서명 검증 중..."
    );

    /*
     * 5. 로그인 검증 요청
     */
    const finishResponse = await fetch(
        "/auth/login/finish",
        {
          method: "POST",
          headers: {
            "Content-Type":
                "application/json",
          },
          credentials: "include",
          body: JSON.stringify({
            username,
            challengeId,
            credential,
          }),
        }
    );

    let finishData;

    try {
      finishData =
          await finishResponse.json();
    } catch {
      throw new Error(
          `로그인 검증 응답을 읽을 수 없습니다. HTTP ${finishResponse.status}`
      );
    }

    console.log(
        "로그인 완료 응답:",
        finishData
    );

    if (!finishResponse.ok) {
      throw new Error(
          finishData.error ||
          finishData.message ||
          `로그인 검증 실패 (HTTP ${finishResponse.status})`
      );
    }

    /*
     * 위험도에 따른 화면 처리
     */
    if (
        finishData.riskAction === "BLOCKED"
    ) {
      setStatus(
          finishData.message ||
          "위험도가 높아 로그인이 차단되었습니다."
      );
      return;
    }

    if (
        finishData.riskAction === "RE_AUTH" ||
        finishData
            .requiresReauthentication
    ) {
      setStatus(
          finishData.message ||
          "추가 인증이 필요합니다."
      );
      return;
    }

    if (finishData.success) {
      setStatus(
          `로그인 성공 · 위험도: ${
              finishData.riskLevel || "low"
          } · 점수: ${
              finishData.riskScore ?? 0
          }`
      );

      /*
       * 대시보드는 구현 제외로 확정했으므로
       * dashboard.html로 이동하지 않는다.
       */
      return;
    }

    throw new Error(
        finishData.message ||
        "로그인에 실패했습니다."
    );
  } catch (error) {
    console.error(
        "로그인 오류:",
        error
    );

    setStatus(
        `오류 발생: ${error.message}`
    );
  }
}


/*
 * HTML에서 onclick="startPasskeyLogin()"으로
 * 호출하는 경우를 위해 전역에 등록
 */
window.startPasskeyLogin =
    startPasskeyLogin;