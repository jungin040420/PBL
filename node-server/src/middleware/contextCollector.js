const { use } = require("react");

const collectContext = (req, res, next) => {
    const ip = requestIp.getClientIp(req) || req.ip;
    const userAgent = req.headers('user-agent') || 'unknown';
    const deviceInfo = parseUserAgent(userAgent);
    const accessTime = new Date().toISOString();
    const hour = new Date().getHours();
    const isNightAccess = hour < 6 || hour >= 22;

    req.context = {
        ip, userAgent, deviceInfo, accessTime, isNightAccess
    };

    console.log('수집한 컨텍스트: ',req.context);
    next();
};

//User-Agent 파싱
const parseUserAgent = (userAgent) => {
    const isMobile = /mobile/i.test(userAgent);
    const isTablet = /tablet/i.test(userAgent);
    const isWindows = /windows/i.test(userAgent);
    const isMac = /macintosh/i.test(userAgent);
    const isAndroid = /android/i.test(userAgent);

    let deviceType = 'desktop';
    if (isMobile) deviceType = 'mobile';
    if (isTablet) deviceType = 'tablet';

    let os = 'unknown';
    if (isWindows) os = 'windows';
    if (isMac) os = 'mac';
    if (isAndroid) os = 'android';
    if (isIOS) os = 'ios';

    return {deviceType, os};
};

module.exports = {collectContext};