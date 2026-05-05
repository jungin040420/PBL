function setStatus(msg) {
  document.getElementById('status').textContent = msg;
}

function base64ToUint8Array(base64url) {
  const base64 = base64url
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .padEnd(base64url.length + (4 - base64url.length % 4) % 4, '=');
  return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}

async function startPasskeyLogin() {
  const username = document.getElementById('username').value.trim();

  if (!username) {
    alert('아이디를 입력해주세요.');
    return;
  }

  try {
    // 1. 서버에 challenge 요청
    setStatus('서버에서 challenge 요청 중...');
    const res = await fetch('/auth/login/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username }),
    });
    const options = await res.json();
    console.log('서버 응답 options:', options);

    const rpId = window.location.hostname;

    // 2. 생체인증 팝업
    setStatus('생체인증 팝업 대기 중...');
    const credential = await navigator.credentials.get({
      publicKey: {
        challenge: base64ToUint8Array(options.challenge),
        rpId: rpId,
        userVerification: 'preferred',
        allowCredentials: (options.allowCredentials || []).map(cred => ({
            id: base64ToUint8Array(cred.id),
            type: 'public-key',
        })),
      },
    });
    console.log('credential:', credential);

    // 3. 서버로 전송
    setStatus('로그인 확인 중...');
    const loginRes = await fetch('/auth/login/finish', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username,
        credential: {
          id: credential.id,
          rawId: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))),
          type: credential.type,
          response: {
            clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON))),
            authenticatorData: btoa(String.fromCharCode(...new Uint8Array(credential.response.authenticatorData))),
            signature: btoa(String.fromCharCode(...new Uint8Array(credential.response.signature))),
          },
        },
      }),
    });
    const loginResult = await loginRes.json();
    console.log('로그인 결과:', loginResult);

    if (loginResult.success) {
      setStatus('로그인 성공!');
      // **추후 코드 수정**
      // location.href = '/dashboard.html';
    } else {
      setStatus('로그인 실패: ' + loginResult.error);
    }

  } catch (error) {
    console.error('로그인 오류:', error);
    setStatus('오류 발생: ' + error.message);
  }
}