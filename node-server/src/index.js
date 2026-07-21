const crypto = require("crypto");
const express = require("express");
const axios = require("axios");

const app = express();
const PORT = 3000;

// Python FastAPI 리스크 서버 주소
const RISK_API_URL =
    process.env.RISK_API_URL || "http://127.0.0.1:5000/risk";

// Elasticsearch 주소
const ELASTICSEARCH_URL =
    process.env.ELASTICSEARCH_URL ||
    "http://localhost:9200/auth-logs/_doc";

app.use(express.json());

// SHA-256 해싱 함수
function hashData(data) {
  return crypto
      .createHash("sha256")
      .update(String(data))
      .digest("hex");
}

// 클라이언트 IP 정리
function normalizeIp(ip) {
  if (!ip) {
    return "127.0.0.1";
  }

  // IPv4가 IPv6 형식으로 표현되는 경우 제거
  return ip.replace("::ffff:", "");
}

// JavaScript 요일을 Python 규칙으로 변환
// JavaScript: 일요일=0, 월요일=1
// Python 요청: 월요일=0, 일요일=6
function convertDayOfWeek(date) {
  return (date.getDay() + 6) % 7;
}

// Python FastAPI 리스크 서버 호출
async function analyzeRisk(payload) {
  try {
    const response = await axios.post(
        RISK_API_URL,
        payload,
        {
          headers: {
            "Content-Type": "application/json"
          },
          timeout: 5000
        }
    );

    console.log("Python 리스크 분석 성공:", response.data);

    return response.data;
  } catch (error) {
    console.error(
        "Python 리스크 API 호출 실패:",
        error.response?.data || error.message
    );

    return null;
  }
}

// Elasticsearch 로그 전송
async function sendLog(log) {
  try {
    await axios.post(
        ELASTICSEARCH_URL,
        log,
        {
          headers: {
            "Content-Type": "application/json"
          },
          timeout: 3000
        }
    );

    console.log("Elasticsearch 로그 전송 성공");
  } catch (error) {
    // Elasticsearch가 실행되지 않아도 로그인 API는 계속 동작
    console.error(
        "Elasticsearch 로그 전송 실패:",
        error.response?.data || error.message
    );
  }
}

// 서버 상태 확인
app.get("/", (req, res) => {
  res.json({
    status: "Node.js 서버 실행 중",
    node_server: `http://localhost:${PORT}`,
    risk_api: RISK_API_URL,
    login_api: "POST /login"
  });
});

// 실제 로그인 요청 및 Python 리스크 분석
app.post("/login", async (req, res) => {
  const time = new Date();

  const ip = normalizeIp(
      req.body.ip ||
      req.headers["x-forwarded-for"] ||
      req.ip
  );

  const userAgent =
      req.body.device ||
      req.headers["user-agent"] ||
      "Unknown";

  const userId =
      req.body.user_id ||
      "real_user";

  // Python LogData 모델과 동일한 요청 구조
  const riskPayload = {
    user_id: String(userId),
    ip: String(ip),
    device: String(userAgent),

    country: req.body.country || "KR",

    login_frequency:
        Number(req.body.login_frequency) || 0,

    login_failures:
        Number(req.body.login_failures) || 0,

    ip_changed:
        req.body.ip_changed === true,

    user_agent_changed:
        req.body.user_agent_changed === true,

    is_new_device:
        req.body.is_new_device === true,

    location_changed:
        req.body.location_changed === true,

    challenge_response_time:
        req.body.challenge_response_time !== undefined &&
        req.body.challenge_response_time !== null
            ? Number(req.body.challenge_response_time)
            : null,

    login_hour:
        req.body.login_hour !== undefined
            ? Number(req.body.login_hour)
            : time.getHours(),

    day_of_week:
        req.body.day_of_week !== undefined
            ? Number(req.body.day_of_week)
            : convertDayOfWeek(time),

    is_phishing_url:
        req.body.is_phishing_url === true
  };

  console.log("Python으로 전송할 데이터:", riskPayload);

  const riskResult = await analyzeRisk(riskPayload);

  // Python 서버 호출 실패 시
  if (!riskResult) {
    return res.status(503).json({
      message: "Python 리스크 서버 호출에 실패했습니다.",
      authentication_action: "RE_AUTH"
    });
  }

  // Elasticsearch 저장용 로그
  const logData = {
    timestamp: time.toISOString(),

    // 로그 발생 위치
    source: "node-auth-server",

    expire_at: new Date(
        Date.now() + 7 * 24 * 60 * 60 * 1000
    ).toISOString(),

    user_id: hashData(userId),
    event_type: "real_login_attempt",
    ip_address: hashData(ip),
    user_agent: userAgent,

    risk_score: riskResult.risk_score,
    risk_level: riskResult.risk_level,
    authentication_action:
    riskResult.authentication_action,

    risk_reason: riskResult.message,
    triggers: riskResult.triggers,
    feature_scores: riskResult.feature_scores
  };

  console.log("로그인 분석 결과:", logData);

  // Elasticsearch 전송 실패와 관계없이 응답 반환
  await sendLog(logData);

  // Python이 결정한 인증 정책에 따라 HTTP 상태 설정
  let statusCode = 200;

  if (riskResult.authentication_action === "RE_AUTH") {
    statusCode = 202;
  }

  if (riskResult.authentication_action === "BLOCKED") {
    statusCode = 403;
  }

  return res.status(statusCode).json({
    message: riskResult.message,
    risk: riskResult,
    logData
  });
});

// 존재하지 않는 주소 처리
app.use((req, res) => {
  res.status(404).json({
    message: "존재하지 않는 API입니다."
  });
});

// 서버 오류 처리
app.use((error, req, res, next) => {
  console.error("Node 서버 오류:", error);

  res.status(500).json({
    message: "Node 서버 내부 오류가 발생했습니다."
  });
});

// Node 서버 실행
app.listen(PORT, () => {
  console.log(`서버 실행 중 → http://localhost:${PORT}`);
  console.log(`Python 리스크 API → ${RISK_API_URL}`);
});