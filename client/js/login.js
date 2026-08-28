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

function toBase64url(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

async function generateFingerprint() {
  const components = [
    navigator.userAgent,
    navigator.language,
    screen.width + 'x' + screen.height,
    screen.colorDepth,
    new Date().getTimezoneOffset(),
    navigator.hardwareConcurrency || 'unknown',
    navigator.platform,
  ];

  const raw = components.join('|');
  const encoder = new TextEncoder();
  const data = encoder.encode(raw);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function startPasskeyLogin() {
  const username = document.getElementById('username').value.trim();

  if (!username) {
    alert('아이디를 입력해주세요.');
    return;
  }

  try {
    setStatus('서버에서 challenge 요청 중...');
    const res = await fetch('/auth/login/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username }),
    });
    const options = await res.json();
    console.log('서버 응답 options:', options); // ← 확인용
    console.log('options.challengeId:', options.challengeId);

    const rpId = window.location.hostname;

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

    const fingerprint = await generateFingerprint()

    setStatus('로그인 확인 중...');
    console.log('전송할 challengeId:', options.challengeId);
    const loginRes = await fetch('/auth/login/finish', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username,
        challengeId: options.challengeId,
        fingerprint,
        credential: {
          id: credential.id,
          rawId: toBase64url(credential.rawId),
          type: credential.type,
          response: {
            clientDataJSON: toBase64url(
              credential.response.clientDataJSON
            ),
            authenticatorData: toBase64url(
              credential.response.authenticatorData
            ),
            signature: toBase64url(
              credential.response.signature
            ),
          },
        },
      }),
    });
    const loginResult = await loginRes.json();
    console.log('로그인 결과:', loginResult); // ← 확인용

    if (loginResult.success) {
      setStatus(`환영합니다, ${username}님!`);
      // 대시보드 연결
      // location.href = '/dashboard.html';
      document.getElementById('loginFormArea').style.display = 'none';
      document.getElementById('authBtnGroup').style.display = 'none';
      document.getElementById('logoutBtn').style.display = 'block';

    } else {
      setStatus('로그인 실패: ' + loginResult.error);
    }

  } catch (error) {
    console.error('로그인 오류:', error);
    setStatus('오류 발생: ' + error.message);
  }
}

async function startLogout() {
  try {
    setStatus('로그아웃 처리 중...');
    const res = await fetch('/auth/logout', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    const result = await res.json();

    if (result.success) {
      setStatus('로그아웃 되었습니다.');
      
      // UI를 초기 로그인 상태로 복구
      document.getElementById('loginFormArea').style.display = 'block';
      document.getElementById('authBtnGroup').style.display = 'flex';
      document.getElementById('logoutBtn').style.display = 'none';
      document.getElementById('username').value = '';
    } else {
      setStatus('로그아웃 실패: ' + result.error);
    }
  } catch (error) {
    console.error('로그아웃 오류:', error);
    setStatus('로그아웃 중 오류 발생');
  }
}