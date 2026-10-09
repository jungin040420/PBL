const webauthnService = require('../services/webauthnService');
const verificationService = require('../services/verificationService');
const sessionManager = require('../services/sessionManager');
const { sendRiskData } = require('../services/riskService');
const { db, authdb, redisClient } = require('../../config/db');
const { hashForCompare, hashUserId } = require('../utils/anonymize');
const { encryptObject } = require('../utils/crypto');
const otpService = require('../services/otpService');
const { createStepupState, getStepupState, completeStepupState } = require('../services/session');
const { updateSessionStatus: updateSessionStatusRaw } = require('../services/session');

// F-08 규칙 5: hashUserId 입력은 DB PK. PK가 없는 경우(미등록 계정, 등록 실패)는 고정 상수 사용 (담당자 확인 필요)
const UNKNOWN_USER_ID = 'UNKNOWN_USER';
const toUserIdHash = (id) => hashUserId(String(id ?? UNKNOWN_USER_ID));

exports.registerStart = async (req, res) => {
    try {
        const { username, displayName, email } = req.body;

        if (!username || !displayName) {
            return res.status(400).json({ error: '필수 입력값 누락' });
        }

        const options = await webauthnService.generateRegistrationOptions(
            username, displayName
        );

        return res.status(200).json(options);

    } catch (error) {
        console.error('registerStart 오류:', error);
        return res.status(500).json({ error: '서버 오류' });
    }
};

exports.registerFinish = async (req, res) => {
    const { username } = req.body;
    try {
        const { email, challengeId, credential, authenticatorAttachment } = req.body;
        const context = req.context || {};

        const result = await verificationService.verifyRegistration(
            username, email, challengeId, credential, authenticatorAttachment
        );

        if (!result.verified) {
            const failUserIdHash = toUserIdHash(null);

            await authdb.query(
                `INSERT INTO access_logs (user_id, auth_result, reason) VALUES (?, 'fail', ?)`,
                [failUserIdHash, 'REGISTER_FAIL']
            );

            try {
                await db.query(
                    'INSERT INTO mfa_db.audit_logs (event_type, payload) VALUES (?, ?)',
                    ['REGISTER_FAIL', encryptObject({
                        userIdHash: failUserIdHash,
                        deviceType: context.deviceInfo?.deviceType || 'unknown',
                        result: 'fail',
                        timestamp: new Date().toISOString(),
                    })]
                );
            } catch (auditError) {
                console.error('[AUDIT_LOG_FAILURE] audit_logs 기록 실패(등록 실패):', auditError.message);
            }

            return res.status(400).json({ error: '등록 검증 실패' });
        }

        // verifyRegistration이 { verified: true, userId }를 반환해야 함
        const userIdHash = toUserIdHash(result.userId);

        await authdb.query(
            `INSERT INTO access_logs (user_id, auth_result, reason) VALUES (?, 'success', ?)`,
            [userIdHash, 'REGISTER_SUCCESS']
        );

        try {
            await db.query(
                'INSERT INTO mfa_db.audit_logs (event_type, payload) VALUES (?, ?)',
                ['REGISTER_SUCCESS', encryptObject({
                    userIdHash,
                    deviceType: context.deviceInfo?.deviceType || 'unknown',
                    result: 'success',
                    timestamp: new Date().toISOString(),
                })]
            );
        } catch (auditError) {
            console.error('[AUDIT_LOG_FAILURE] audit_logs 기록 실패(등록):', auditError.message);
        }

        return res.status(200).json({ success: true, message: '등록 완료' });

    } catch (error) {
        console.error('registerFinish 오류:', error);

        if (username) {
            try {
                const throwUserIdHash = toUserIdHash(null);

                await authdb.query(
                    `INSERT INTO access_logs (user_id, auth_result, reason) VALUES (?, 'fail', ?)`,
                    [throwUserIdHash, 'REGISTER_FAIL']
                );

                await db.query(
                    'INSERT INTO mfa_db.audit_logs (event_type, payload) VALUES (?, ?)',
                    ['REGISTER_FAIL', encryptObject({
                        userIdHash: throwUserIdHash,
                        result: 'fail',
                        reason: error.message || 'UNKNOWN_ERROR',
                        timestamp: new Date().toISOString(),
                    })]
                );
            } catch (logError) {
                console.error('[AUDIT_LOG_FAILURE] catch 블록 감사 로그 실패:', logError.message);
            }
        }
        return res.status(500).json({ error: '서버 오류' });
    }
};

exports.loginStart = async (req, res) => {
    try {
        const { username } = req.body;

        if (!username) {
            return res.status(400).json({ error: '아이디를 입력하세요' });
        }

        const [rows] = await db.query(
            `SELECT id FROM users WHERE username = ? LIMIT 1`,
            [username]
        );
        const userId = rows[0]?.id ?? null;

        if (userId) {
            await redisClient.set(
                `challenge:time:${userId}`,
                String(Date.now()),
                { EX: 90 }
            );
        }

        const options = await webauthnService.generateLoginOptions(username);
        return res.status(200).json(options);

    } catch (error) {
        console.error('loginStart 오류:', error);
        return res.status(500).json({ error: '서버 오류' });
    }
};

exports.loginFinish = async (req, res) => {
    const { username } = req.body;
    let userId = null;   // catch 블록에서도 사용하도록 try 밖에서 선언

    // 성능 측정 (PERF_LOG=true 일 때만 Server-Timing 헤더 출력)
    const t = {};
    const t0 = performance.now();
    let s = t0;
    const setTiming = () => {
        if (process.env.PERF_LOG !== 'true') return;
        t.total = performance.now() - t0;
        res.set('Server-Timing',
            Object.entries(t).map(([k, v]) => `${k};dur=${v.toFixed(1)}`).join(', '));
    };

    try {
        const { challengeId, credential, fingerprint } = req.body;
        const context = req.context || {};
        context.fingerprint = fingerprint;

        const [userRows] = await db.query(
            `SELECT id, email FROM users WHERE username = ? LIMIT 1`,
            [username]
        );
        userId = userRows[0]?.id ?? null;

        if (userId) {
            const startTime = await redisClient.get(`challenge:time:${userId}`);
            context.challengeResponseTime = startTime
                ? Date.now() - parseInt(startTime, 10)
                : null;
            await redisClient.del(`challenge:time:${userId}`);
        } else {
            context.challengeResponseTime = null;
        }

        context.loginRegion = String(context.country || 'UNKNOWN').trim().toUpperCase();
        t.pre = performance.now() - s;

        const result = await verificationService.verifyLogin(
            username, challengeId, credential
        );
        console.log('verifyLogin 결과:', result);

        Object.assign(t, result.timing);
        s = performance.now();

        // 로그인 실패 시
        if (!result.verified) {
            const failUserIdHash = toUserIdHash(userId);

            await authdb.query(
                `INSERT INTO access_logs 
                (user_id, auth_result, reason)
                VALUES (?, 'fail', ?)`,
                [failUserIdHash, result.reason || 'VERIFICATION_FAILED']
            );

            try {
                await db.query(
                    'INSERT INTO mfa_db.audit_logs (event_type, payload) VALUES (?, ?)',
                    ['LOGIN_FAIL', encryptObject({
                        userIdHash: failUserIdHash,
                        deviceType: context.deviceInfo?.deviceType || 'unknown',
                        result: 'fail',
                        reason: result.reason || 'VERIFICATION_FAILED',
                        timestamp: new Date().toISOString(),
                    })]
                );
            } catch (auditError) {
                console.error('[AUDIT_LOG_FAILURE] audit_logs 기록 실패(실패 이벤트):', auditError.message);
            }

            context.signCountAbnormal = result.signCountAbnormal || false;
            context.credentialMismatch = result.credentialMismatch || false;

            const consecutiveFailureCount = userId ? parseInt(
                await redisClient.get(`login:fail:${userId}`), 10
            ) || 0 : 0;
            context.consecutiveFailureCount = consecutiveFailureCount;
            context.failedLoginCount = consecutiveFailureCount;

            const ipHash = hashForCompare(context.ip || '');
            const isBlacklisted = await redisClient.get(`blacklist:ip:${ipHash}`);
            context.blacklistIpDetected = isBlacklisted === '1';

            if (consecutiveFailureCount >= 5) {
                await redisClient.set(
                    `blacklist:ip:${ipHash}`,
                    '1',
                    { EX: 60 * 60 * 24 }
                );
                context.blacklistIpDetected = true;
            }

            let registeredPasskey = null;
            try {
                const [passkeyRows] = await db.query(
                    `SELECT p.id FROM passkeys p
                    JOIN users u ON p.user_id = u.id
                    WHERE u.username = ? AND p.credential_id = ? AND p.is_active = 1 LIMIT 1`,
                    [username, credential?.id || '']
                );
                registeredPasskey = passkeyRows?.[0] || null;
            } catch (passkeyError) {
                console.error('등록 Passkey 확인 실패:', passkeyError.message);
            }

            const failCurrentType = credential?.authenticatorAttachment || 'unknown';
            context.authenticationMethodChanged = (!registeredPasskey || failCurrentType === 'unknown');

            if (userId) {
                await redisClient.incr(`login:fail:${userId}`);
                await redisClient.expire(`login:fail:${userId}`, 3600);
            }

            try {
                await sendRiskData(String(userId ?? UNKNOWN_USER_ID), context);
            } catch (riskError) {
                console.error('리스크 서버 전송 실패:', riskError.message);
            }

            return res.status(401).json({
                error: '로그인 검증 실패',
                reason: result.reason
            });
        }

        // 검증 성공인데 사용자가 없는 경우 (stepup 조회보다 먼저 차단)
        if (!userId) {
            return res.status(404).json({ error: '사용자를 찾을 수 없습니다.' });
        }

        // step-up 완료 감지
        const stepupState = await getStepupState(userId);

        if (stepupState === 'PENDING') {
            const currentSessionToken = req.cookies?.session;
            if (currentSessionToken) {
                const [tokenUserId, tokenSessionId] = currentSessionToken.split(':');

                if (String(tokenUserId) === String(userId) && tokenSessionId) {
                    const activated = await updateSessionStatusRaw(userId, tokenSessionId, 'ACTIVE');

                    if (!activated) {
                        return res.status(401).json({
                            success: false,
                            error: 'STEPUP_SESSION_INVALID',
                            message: '재인증 대상 세션이 유효하지 않습니다.',
                        });
                    }

                    await completeStepupState(userId);

                    return res.status(200).json({
                        success: true,
                        stepupCompleted: true,
                        message: '재인증이 완료되었습니다.',
                    });
                }
            }

            return res.status(401).json({
                success: false,
                error: 'STEPUP_SESSION_MISSING',
                message: '다시 로그인해주세요.',
            });
        }

        // 로그인 성공 시
        const failedLoginCount = parseInt(
            await redisClient.get(`login:fail:${userId}`), 10
        ) || 0;
        context.failedLoginCount = failedLoginCount;
        context.consecutiveFailureCount = failedLoginCount;

        context.signCountAbnormal = result.signCountAbnormal || false;
        context.credentialMismatch = result.credentialMismatch || false;
        context.authenticationMethodChanged = false;

        const blacklistIpHash = hashForCompare(context.ip || '');
        const blacklistStatus = await redisClient.get(`blacklist:ip:${blacklistIpHash}`);
        context.blacklistIpDetected = blacklistStatus === '1';

        await redisClient.del(`login:fail:${userId}`);

        const userIdHash = toUserIdHash(userId);
        const contextKey = `lastcontext:${userIdHash}`;
        const prevContext = await redisClient.hGetAll(contextKey);

        const currentDeviceHash = hashForCompare(JSON.stringify(context.deviceInfo || {}));
        const currentIpHash = hashForCompare(context.ip || '');
        const currentUaHash = hashForCompare(context.userAgent || '');
        const currentCountry = String(context.country || 'UNKNOWN').trim().toUpperCase();
        const currentCountryHash = hashForCompare(currentCountry);
        const unknownCountryHash = hashForCompare('UNKNOWN');

        context.hasPreviousContext = Object.keys(prevContext).length > 0;
        context.deviceChanged = context.hasPreviousContext
            ? prevContext.deviceHash !== currentDeviceHash : false;
        context.ipChanged = context.hasPreviousContext
            ? prevContext.ipHash !== currentIpHash : false;
        context.userAgentChanged = context.hasPreviousContext
            ? prevContext.uaHash !== currentUaHash : false;

        // 지역 조회 실패(UNKNOWN)나 이전 값 없음/UNKNOWN은 변경으로 보지 않음 (오탐 방지)
        context.regionChanged =
            context.hasPreviousContext &&
            currentCountry !== 'UNKNOWN' &&
            Boolean(prevContext.countryHash) &&
            prevContext.countryHash !== unknownCountryHash
                ? prevContext.countryHash !== currentCountryHash
                : false;
        context.locationChanged = context.regionChanged;   // riskService 호환

        // F-08 규칙 6: 원본 country는 저장하지 않고 해시만 저장
        const nextContext = {
            deviceHash: String(currentDeviceHash || ''),
            ipHash: String(currentIpHash || ''),
            uaHash: String(currentUaHash || ''),
        };
        if (currentCountry !== 'UNKNOWN') {
            nextContext.countryHash = String(currentCountryHash);
        }
        await redisClient.hSet(contextKey, nextContext);
        await redisClient.expire(contextKey, 60 * 60 * 24 * 30);

        let successregisteredType = 'unknown';
        try {
            const [passkeyRows] = await db.query(
                `SELECT p.authenticator_type FROM passkeys p
                JOIN users u ON p.user_id = u.id
                WHERE u.username = ? AND p.credential_id = ? AND p.is_active = 1 LIMIT 1`,
                [username, credential.id]
            );
            successregisteredType = passkeyRows?.[0]?.authenticator_type || 'unknown';
        } catch (e) {
            console.error('authenticator_type 조회 실패:', e.message);
        }
        const successcurrentType = credential.authenticatorAttachment || 'unknown';
        context.authenticationMethodChanged = successregisteredType !== successcurrentType;

        t.context = performance.now() - s; s = performance.now();

        await authdb.query(
            `INSERT INTO access_logs 
            (user_id, auth_result, reason)
            VALUES (?, 'success', ?)`,
            [userIdHash, 'LOGIN_SUCCESS']
        );

        try {
            await db.query(
                'INSERT INTO mfa_db.audit_logs (event_type, payload) VALUES (?, ?)',
                ['LOGIN_SUCCESS', encryptObject({
                    userIdHash,
                    deviceType: context.deviceInfo?.deviceType || 'unknown',
                    result: 'success',
                    timestamp: new Date().toISOString(),
                })]
            );
        } catch (auditError) {
            console.error('[AUDIT_LOG_FAILURE] audit_logs 기록 실패:', auditError.message);
        }
        t.audit = performance.now() - s;

        const loginFrequency = await redisClient.incr(`login:count:${userId}`);
        await redisClient.expire(`login:count:${userId}`, 3600);
        context.loginFrequency = loginFrequency;

        s = performance.now();

        // 리스크 스코어
        let riskScore = 0;
        let riskLevel = 'LOW';
        let riskAction = 'ACTIVE';
        let riskMessage = '리스크 분석 서버 응답 없음';
        let riskTriggers = [];
        let riskFeatureScores = {};
        let mlModelUsed = false;
        let mlModelType = null;
        let mlAnomalyScore = null;
        let mlIsAnomaly = null;

        try {
            console.log('[RISK CONTEXT DEBUG]', {
                hasPreviousContext: context.hasPreviousContext,
                regionChanged: context.regionChanged,
                ipChanged: context.ipChanged
            });

            const riskResult = await sendRiskData(String(userId), context);
            riskScore = riskResult.score ?? 0;
            riskLevel = riskResult.level ?? 'LOW';
            riskAction = riskResult.action ?? 'ACTIVE';
            riskMessage = riskResult.message ?? '리스크 분석 완료';
            riskTriggers = riskResult.triggers ?? [];
            riskFeatureScores = riskResult.featureScores ?? {};
            mlModelUsed = riskResult.mlModelUsed ?? false;
            mlModelType = riskResult.mlModelType ?? null;
            mlAnomalyScore = riskResult.mlAnomalyScore ?? null;
            mlIsAnomaly = riskResult.mlIsAnomaly ?? null;
            console.log('리스크 스코어:', { riskScore, riskLevel, riskAction, mlModelUsed });
        } catch (error) {
            console.error('리스크 스코어 요청 실패:', error.message);
        }
        t.risk = performance.now() - s; s = performance.now();

        if (riskAction === 'BLOCKED') {
            setTiming();
            return res.status(403).json({
                success: false,
                message: riskMessage || '위험도가 높아 로그인이 차단되었습니다.',
                riskScore, riskLevel, riskAction,
                triggers: riskTriggers,
                featureScores: riskFeatureScores,
                ml: {
                    modelUsed: mlModelUsed, modelType: mlModelType,
                    anomalyScore: mlAnomalyScore, isAnomaly: mlIsAnomaly
                },
            });
        }

        if (riskAction === 'RE_AUTH') {
            const email = userRows[0].email;

            const session = await sessionManager.createSession(
                userId, context.ip, context.userAgent, context.fingerprint, 'RE_AUTH'
            );
            t.session = performance.now() - s; s = performance.now();

            try {
                await otpService.generateAndSendOtp(userId, email);
            } catch (otpError) {
                console.error('OTP 발송 실패:', otpError.message);
                t.otp = performance.now() - s;
                setTiming();
                await sessionManager.deleteSession(session.token);
                return res.status(503).json({
                    success: false,
                    error: '인증 코드 발송에 실패했습니다. 잠시 후 다시 시도해주세요.',
                });
            }
            t.otp = performance.now() - s;
            setTiming();

            const isNgrok = req.headers.host?.includes('ngrok');
            res.cookie('session', session.token, {
                httpOnly: true,
                secure: isNgrok ? true : false,
                sameSite: isNgrok ? 'none' : 'lax',
                maxAge: 1000 * 60 * 60,
            });

            return res.status(200).json({
                success: false,
                requiresReauthentication: true,
                message: riskMessage || '이메일로 전송된 인증 코드를 입력해주세요.',
                riskScore, riskLevel, riskAction,
                triggers: riskTriggers,
                featureScores: riskFeatureScores,
                ml: {
                    modelUsed: mlModelUsed, modelType: mlModelType,
                    anomalyScore: mlAnomalyScore, isAnomaly: mlIsAnomaly
                },
            });
        }

        const session = await sessionManager.createSession(
            userId, context.ip, context.userAgent, fingerprint
        );
        t.session = performance.now() - s;
        setTiming();
        console.log('세션 생성 결과:', session);

        const isNgrok = req.headers.host?.includes('ngrok');
        res.cookie('session', session.token, {
            httpOnly: true,
            secure: isNgrok ? true : false,
            sameSite: isNgrok ? 'none' : 'lax',
            maxAge: 1000 * 60 * 60,
        });

        return res.status(200).json({
            success: true,
            message: '로그인 성공',
            context: {
                deviceType: context.deviceInfo?.deviceType,
                os: context.deviceInfo?.os,
                isNightAccess: context.isNightAccess,
                country: context.country,
                regionChanged: context.regionChanged,
                signCountAbnormal: context.signCountAbnormal,
            },
            riskScore, riskLevel, riskAction, riskMessage,
            triggers: riskTriggers,
            featureScores: riskFeatureScores,
            ml: {
                modelUsed: mlModelUsed, modelType: mlModelType,
                anomalyScore: mlAnomalyScore, isAnomaly: mlIsAnomaly
            },
        });

    } catch (error) {
        console.error('loginFinish 오류:', error);

        if (username) {
            try {
                const throwUserIdHash = toUserIdHash(userId);

                await authdb.query(
                    `INSERT INTO access_logs (user_id, auth_result, reason) VALUES (?, 'fail', ?)`,
                    [throwUserIdHash, 'LOGIN_FAIL']
                );

                await db.query(
                    'INSERT INTO mfa_db.audit_logs (event_type, payload) VALUES (?, ?)',
                    ['LOGIN_FAIL', encryptObject({
                        userIdHash: throwUserIdHash,
                        result: 'fail',
                        reason: error.message || 'UNKNOWN_ERROR',
                        timestamp: new Date().toISOString(),
                    })]
                );
            } catch (logError) {
                console.error('[AUDIT_LOG_FAILURE] catch 블록 감사 로그 실패:', logError.message);
            }
        }
        return res.status(500).json({ error: '서버 오류' });
    }
};

exports.logout = async (req, res) => {
    try {
        const sessionToken = req.cookies.session;
        if (sessionToken) {
            await sessionManager.deleteSession(sessionToken);
        }
        res.clearCookie('session');
        return res.status(200).json({ success: true, message: '로그아웃 완료' });
    } catch (error) {
        console.error('logout 오류:', error);
        return res.status(500).json({ error: '서버 오류' });
    }
};

exports.verifySession = async (req, res) => {
    try {
        const sessionToken = req.cookies.session;
        if (!sessionToken) {
            return res.status(401).json({ error: '토큰 없음' });
        }

        const context = req.context || {};

        const result = await sessionManager.verifySession(sessionToken, context.ip, context.userAgent);
        if (!result.valid) {
            res.clearCookie('session');
        }

        return res.status(200).json({ success: true, username: result.username });
    } catch (error) {
        console.error('verifySession 오류:', error);
        return res.status(500).json({ error: '서버 오류' });
    }
};

exports.reauthVerify = async (req, res) => {
    try {
        const sessionToken = req.cookies.session;
        if (!sessionToken) {
            return res.status(401).json({ error: '세션이 없습니다' });
        }

        const { otp } = req.body;
        if (!otp || typeof otp !== 'string') {
            return res.status(400).json({ error: 'OTP를 입력해주세요' });
        }

        const [userId, sessionId] = sessionToken.split(':');
        if (!userId || !sessionId) {
            return res.status(401).json({ error: '유효하지 않은 세션입니다' });
        }

        const result = await otpService.verifyOtp(userId, otp);

        if (!result.valid) {
            if (result.reason === 'REAUTH_EXPIRED' || result.reason === 'REAUTH_BLOCKED') {
                await sessionManager.updateSessionStatus(userId, sessionId, 'BLOCKED');
                res.clearCookie('session');
            }
            return res.status(401).json({ error: '인증 실패', reason: result.reason });
        }

        await sessionManager.updateSessionStatus(userId, sessionId, 'ACTIVE');
        return res.status(200).json({ success: true, message: '인증 완료' });

    } catch (error) {
        console.error('reauthVerify 오류:', error);
        return res.status(500).json({ error: '서버 오류' });
    }
};