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
      document.getElementById('loginFormArea').style.display = 'none';
      document.getElementById('authBtnGroup').style.display = 'none';
      document.getElementById('logoutBtn').style.display = 'block';

    } else if (loginResult.requiresReauthentication) {
      setStatus(loginResult.message || '이메일로 전송된 인증 코드를 입력해주세요.');
      showReauthUI();

    } else {
      setStatus('로그인 실패: ' + (loginResult.message || loginResult.error || '위험도가 높아 로그인이 차단되었습니다.'));
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

let otpTimerInterval = null;

function showReauthUI() {
  document.getElementById('authBtnGroup').style.display = 'none';
  document.getElementById('reauthArea').style.display = 'flex';
  document.getElementById('otpInput').value = '';
  document.getElementById('otpInput').focus();
  startOtpCountdown(180); // REAUTH_TTL과 동일한 값(초)
}

function hideReauthUI() {
  document.getElementById('reauthArea').style.display = 'none';
  document.getElementById('authBtnGroup').style.display = 'flex';
  if (otpTimerInterval) {
    clearInterval(otpTimerInterval);
    otpTimerInterval = null;
  }
}

function startOtpCountdown(seconds) {
  let remaining = seconds;
  const timerEl = document.getElementById('otpTimer');

  if (otpTimerInterval) clearInterval(otpTimerInterval);

  const tick = () => {
    const m = Math.floor(remaining / 60);
    const s = remaining % 60;
    timerEl.textContent = `남은 시간: ${m}:${String(s).padStart(2, '0')}`;

    if (remaining <= 0) {
      clearInterval(otpTimerInterval);
      timerEl.textContent = '인증 코드가 만료되었습니다. 다시 로그인해주세요.';
      document.getElementById('otpSubmitBtn').disabled = true;
      return;
    }
    remaining -= 1;
  };

  tick();
  otpTimerInterval = setInterval(tick, 1000);
}

async function submitOtp() {
  const otp = document.getElementById('otpInput').value.trim();

  if (!otp || otp.length !== 6) {
    setStatus('6자리 인증 코드를 입력해주세요.');
    return;
  }

  try {
    setStatus('인증 코드 확인 중...');
    document.getElementById('otpSubmitBtn').disabled = true;

    const res = await fetch('/auth/reauth/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ otp }),
    });

    const result = await res.json();
    console.log('재인증 결과:', result);

    if (result.success) {
      setStatus('인증 완료! 로그인되었습니다.');
      hideReauthUI();
      document.getElementById('loginFormArea').style.display = 'none';
      document.getElementById('logoutBtn').style.display = 'block';
      return;
    }

    // 실패 케이스별 메시지 분기
    if (result.reason === 'REAUTH_EXPIRED') {
      setStatus('인증 코드가 만료되었습니다. 처음부터 다시 로그인해주세요.');
      hideReauthUI();
    } else if (result.reason === 'REAUTH_BLOCKED') {
      setStatus('시도 횟수를 초과했습니다. 처음부터 다시 로그인해주세요.');
      hideReauthUI();
    } else {
      setStatus('인증 코드가 일치하지 않습니다. 다시 입력해주세요.');
      document.getElementById('otpSubmitBtn').disabled = false;
      document.getElementById('otpInput').value = '';
      document.getElementById('otpInput').focus();
    }

  } catch (error) {
    console.error('재인증 오류:', error);
    setStatus('오류 발생: ' + error.message);
    document.getElementById('otpSubmitBtn').disabled = false;
  }
}

window.submitOtp = submitOtp;