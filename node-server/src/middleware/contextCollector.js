const requestIp = require('request-ip');
const geoip = require('geoip-lite');

const collectContext = (req, res, next) => {
  const now = new Date();

  const ip = requestIp.getClientIp(req) || req.ip;
  const userAgent = req.headers['user-agent'] || 'unknown';

  const deviceInfo = parseUserAgent(userAgent);
  const accessTime = new Date().toISOString();
  const hour = new Date().getHours();
  const isNightAccess = hour < 6 || hour >= 22;
  const loginHour = hour;
  const dayOfWeek = now.getDay();
  const geo = geoip.lookup(ip);
  const country = (geo?.country || 'UNKNOWN').toUpperCase();

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
    clientIp: ip,
    forwardedFor: req.headers['x-forwarded-for'] || null,
    realIp: req.headers['x-real-ip'] || null,
    geo,
    country,
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
    geoLookupSucceeded: Boolean(geo)
  });

  next();
};

const parseUserAgent = (userAgent) => {
  const isMobile = /mobile/i.test(userAgent);
  const isTablet = /tablet/i.test(userAgent);
  const isWindows = /windows/i.test(userAgent);
  const isMac = /macintosh/i.test(userAgent);
  const isAndroid = /android/i.test(userAgent);
  const isIOS = /iphone|ipad/i.test(userAgent);

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
    os
  };
};

module.exports = {
  collectContext
};
