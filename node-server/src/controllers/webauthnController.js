const webauthnService = require('../services/webauthnService');
const verificationService = require('../services/verificationService');
const sessionManager = require('../services/sessionManager');
const { sendRiskData } = require('../services/riskService');
const { db, authdb, redisClient } = require('../../config/db');
const { hashForCompare, hashUserId } = require('../utils/anonymize');
const { encryptObject } = require('../utils/crypto');
const otpService = require('../services/otpService');

exports.registerStart = async (req, res) => {
    try {
        const { username, displayName, email } = req.body;

        // 추후 코드 수정
        //   - username 중복 체크
        //   - 이메일 형식 검증
        //   - 특수문자 제한 등
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
            const failUserIdHash = hashUserId(username);

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

        const userIdHash = hashUserId(username);

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

        // 추후 코드 수정
        //   - 등록 완료 후 바로 로그인 처리할지 여부
        return res.status(200).json({ success: true, message: '등록 완료' });

    } catch (error) {
        console.error('registerFinish 오류:', error);

        if (username) {
            try {
                const throwUserIdHash = hashUserId(username);

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

        //  추후 코드 수정
        //   - 타이밍 공격 방지
        //   - 계정 열거 공격 방지
        if (!username) {
            return res.status(400).json({ error: '아이디를 입력하세요' });
        }

        await redisClient.set(
            `challenge:time:${username}`,
            String(Date.now()),
            { EX: 300 }
        );

        const options = await webauthnService.generateLoginOptions(username);
        return res.status(200).json(options);

    } catch (error) {
        console.error('loginStart 오류:', error);
        return res.status(500).json({ error: '서버 오류' });
    }
};

exports.loginFinish = async (req, res) => {
    const { username } = req.body;
    try {
        const { challengeId, credential, fingerprint } = req.body;
        const context = req.context || {};
        context.fingerprint = fingerprint;

        const startTime = await redisClient.get(`challenge:time:${username}`);
        const challengeResponseTime = startTime
            ? Date.now() - parseInt(startTime, 10)
            : null;
        context.challengeResponseTime = challengeResponseTime;
        await redisClient.del(`challenge:time:${username}`);

        context.loginRegion = context.country || 'KR';

        const result = await verificationService.verifyLogin(
            username, challengeId, credential
        );
        console.log('verifyLogin 결과:', result);

        // 로그인 실패 시
        if (!result.verified) {
            const failUserIdHash = hashUserId(username);

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

            const consecutiveFailureCount = parseInt(
                await redisClient.get(`login:fail:${username}`)
            ) || 0;
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

            await redisClient.incr(`login:fail:${username}`);
            await redisClient.expire(`login:fail:${username}`, 3600);

            try {
                await sendRiskData(username, context);
            } catch (riskError) {
                console.error('리스크 서버 전송 실패:', riskError.message);
            }

            return res.status(401).json({
                error: '로그인 검증 실패',
                reason: result.reason
            });
        }

        // 로그이 성공 시
        const [rows] = await db.query(
            `SELECT id, username, email FROM users WHERE username = ? LIMIT 1`,
            [username]
        );
        if (!rows || rows.length === 0) {
            return res.status(404).json({ error: '사용자를 찾을 수 없습니다.' });
        }

        const failedLoginCount = parseInt(
            await redisClient.get(`login:fail:${username}`), 10
        ) || 0;
        context.failedLoginCount = failedLoginCount;
        context.consecutiveFailureCount = failedLoginCount;

        context.signCountAbnormal = result.signCountAbnormal || false;
        context.credentialMismatch = result.credentialMismatch || false;
        context.authenticationMethodChanged = false;

        const blacklistIpHash = hashForCompare(context.ip || '');
        const blacklistStatus = await redisClient.get(`blacklist:ip:${blacklistIpHash}`);
        context.blacklistIpDetected = blacklistStatus === '1';

        await redisClient.del(`login:fail:${username}`);

        const userIdHash = hashUserId(username);
        const contextKey = `lastcontext:${userIdHash}`;
        const prevContext = await redisClient.hGetAll(contextKey);

        const currentDeviceHash = hashForCompare(JSON.stringify(context.deviceInfo || {}));
        const currentIpHash = hashForCompare(context.ip || '');
        const currentUaHash = hashForCompare(context.userAgent || '');
        const currentCountryHash = hashForCompare(context.country || 'KR');

        context.hasPreviousContext = Object.keys(prevContext).length > 0;
        context.deviceChanged = context.hasPreviousContext
            ? prevContext.deviceHash !== currentDeviceHash : false;
        context.ipChanged = context.hasPreviousContext
            ? prevContext.ipHash !== currentIpHash : false;
        context.userAgentChanged = context.hasPreviousContext
            ? prevContext.uaHash !== currentUaHash : false;
        context.locationChanged = context.hasPreviousContext
            ? prevContext.countryHash !== currentCountryHash : false;

        await redisClient.hSet(contextKey, {
            deviceHash: String(currentDeviceHash || ''),
            ipHash: String(currentIpHash || ''),
            uaHash: String(currentUaHash || ''),
            countryHash: String(currentCountryHash || ''),
        });
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

        const loginFrequency = await redisClient.incr(`login:count:${username}`);
        await redisClient.expire(`login:count:${username}`, 3600);
        context.loginFrequency = loginFrequency;

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
            const riskResult = await sendRiskData(username, context);
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
            console.log('리스크 스코어:', { riskScore, riskLevel, mlModelUsed });
        } catch (error) {
            console.error('리스크 스코어 요청 실패:', error.message);
        }

        if (riskAction === 'BLOCKED') {
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
            const userId = rows[0].id;
            const email = rows[0].email;

            const session = await sessionManager.createSession(
                userId, context.ip, context.userAgent, context.fingerprint, 'RE-AUTH'
            );

            try {
                await otpService.generateAndSendOtp(userId, email);
            } catch (otpError) {
                console.error('OTP 발송 실패:', otpError.message);
                await sessionManager.deleteSession(session.token);
                return res.status(503).json({
                    success: false,
                    error: '인증 코드 발송에 실패했습니다. 잠시 후 다시 시도해주세요.',
                });
            }

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
            rows[0].id, context.ip, context.userAgent, fingerprint
        );
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
                const throwUserIdHash = hashUserId(username);

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