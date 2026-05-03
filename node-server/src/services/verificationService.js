//MVP 단계
//추후 서명 검증(@simplewebauthn/server), counter 업데이트 구현
const {db, redisClient} = require('../../config/db');
exports.verifyRegistration = async (username, credential) => {
  console.log('받은 username:', username);   
  console.log('받은 credential:', credential);
  
  const [userRows] = await db.query(
    'SELECT id FROM users WHERE username = ?',
    [username]
  );

  let userId;
  if (userRows.length === 0) {
    // 새 사용자 등록
    const [result] = await db.query(
      'INSERT INTO users (username, display_name, email) VALUES (?, ?, ?)',
      [username, username, '']
    );
    userId = result.insertId;
  } else {
    userId = userRows[0].id;
  }

  //키값 수정
  await db.query(
    `INSERT INTO passkeys (user_id, credential_id, public_key, counter)
     VALUES (?, ?, ?, ?)`,
    [userId, credential.id, JSON.stringify(credential), 0]
  );
  await redisClient.del(`challenge:${username}`);

  return { verified: true };
};

exports.verifyLogin = async (username, credential) => {
  const [rows] = await db.query(
    `SELECT p.* FROM passkeys p
     JOIN users u ON p.user_id = u.id
     WHERE u.username = ? AND p.credential_id = ?`,
    [username, credential.id]
  );

  if (rows.length === 0) {
    return { verified: false };
  }
  await redisClient.del(`challenge:${username}`);

  //추후 서명 검증 로직 추가
  return { verified: true };
};