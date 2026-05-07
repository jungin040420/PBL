function getInputs() {
  return {
    username: document.getElementById('username').value.trim(),
    displayName: document.getElementById('displayName').value.trim(),
    email: document.getElementById('email').value.trim(),
  };
}

function setStatus(msg) {
  document.getElementById('status').textContent = msg;
}

function base64ToUint8Array(base64url) {
  const base64 = base64url          // 파라미터: base64url, 변수: base64
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .padEnd(base64url.length + (4 - base64url.length % 4) % 4, '=');
  return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}

function toBase64url(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

async function startPasskeyRegister() {
  const { username, displayName, email } = getInputs();

  if (!username || !displayName || !email) {
    setStatus('모든 항목을 입력해주세요.');
    return;
  }

  try {
    setStatus('서버에서 challenge 요청 중...');
    const res = await fetch('/auth/register/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, displayName, email }),
    });
    const options = await res.json();
    console.log('서버 응답 options:', options);

    const rpId = window.location.hostname;

    setStatus('생체인증 팝업 대기 중...');
    const credential = await navigator.credentials.create({
      publicKey: {
        challenge: base64ToUint8Array(options.challenge),
        rp: {
          id: rpId,
          name: "MFA 보안 시스템"
        },
        user: {
          id: base64ToUint8Array(options.userId),
          name: username,
          displayName: displayName,
        },
        pubKeyCredParams: [
          { type: "public-key", alg: -7 },
          { type: "public-key", alg: -257 },
        ],
      },
    });
    console.log('생성된 credential:', credential);

    setStatus('등록 완료 중...');
    await fetch('/auth/register/finish', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({username, email,
          credential: {
            id: credential.id,
            rawId: toBase64url(credential.rawId),
            type: credential.type,
            response: {
              clientDataJSON: toBase64url(credential.response.clientDataJSON),
                attestationObject: toBase64url(credential.response.attestationObject),
            },
          },  
      }),
    });

    setStatus('등록 완료!');

  } catch (error) {
    console.error('등록 오류:', error);
    setStatus('오류 발생: ' + error.message);
  }
}