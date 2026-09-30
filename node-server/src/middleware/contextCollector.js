const requestIp = require('request-ip');
const geoip = require('geoip-lite');

const normalizeIp = (value) => {
  if (!value) {
    return '';
  }

  return String(value)
      .split(',')[0]
      .trim()
      .replace(/^::ffff:/, '');
};

const collectContext = (req, res, next) => {
  const now = new Date();

  // Cloudflare 또는 리버스 프록시를 통과한 실제 접속 IP 우선 사용
  const forwardedIp =
      req.headers['cf-connecting-ip']
      || req.headers['x-real-ip']
      || req.headers['x-forwarded-for'];

  const requestClientIp = requestIp.getClientIp(req);

  const rawIp =
      forwardedIp
      || requestClientIp
      || req.ip
      || req.socket?.remoteAddress
      || '';

  const ip = normalizeIp(rawIp);
  const userAgent = req.headers['user-agent'] || 'unknown';

  const deviceInfo = parseUserAgent(userAgent);
  const accessTime = now.toISOString();
  const hour = now.getHours();
  const isNightAccess = hour < 6 || hour >= 22;
  const loginHour = hour;
  const dayOfWeek = now.getDay();

  const geo = ip ? geoip.lookup(ip) : null;

  // 조회 실패 시 KR로 고정하면 해외 접속도 KR로 처리될 수 있으므로 UNKNOWN 사용
  const country = String(geo?.country || 'UNKNOWN')
      .trim()
      .toUpperCase();

  req.context = {
    ip,
    userAgent,
    deviceInfo,
    accessTime,
    isNightAccess,
    loginHour,
    dayOfWeek,
    country,
  };

  console.log('[GEOIP DEBUG]', {
    cloudflareIp: req.headers['cf-connecting-ip'] || null,
    realIp: req.headers['x-real-ip'] || null,
    forwardedFor: req.headers['x-forwarded-for'] || null,
    requestClientIp: requestClientIp || null,
    expressIp: req.ip || null,
    remoteAddress: req.socket?.remoteAddress || null,
    rawIp,
    normalizedIp: ip,
    geoResult: geo,
    detectedCountry: country,
  });

  console.log('[CONTEXT DEBUG]', {
    hasIp: Boolean(ip),
    hasUserAgent: Boolean(userAgent),
    deviceInfo,
    accessTime,
    isNightAccess,
    loginHour,
    dayOfWeek,
    country,
    geoLookupSucceeded: Boolean(geo),
  });

  next();
};

const parseUserAgent = (userAgent) => {
  const isMobile = /mobile/i.test(userAgent);
  const isTablet = /tablet|ipad/i.test(userAgent);
  const isWindows = /windows/i.test(userAgent);
  const isMac = /macintosh/i.test(userAgent);
  const isAndroid = /android/i.test(userAgent);
  const isIOS = /iphone|ipad|ipod/i.test(userAgent);

  let deviceType = 'desktop';

  if (isMobile) {
    deviceType = 'mobile';
  }

  if (isTablet) {
    deviceType = 'tablet';
  }

  let os = 'unknown';

  if (isWindows) {
    os = 'windows';
  }

  if (isMac) {
    os = 'mac';
  }

  if (isAndroid) {
    os = 'android';
  }

  if (isIOS) {
    os = 'ios';
  }

  return {
    deviceType,
    os,
  };
};

module.exports = {
  collectContext,
};