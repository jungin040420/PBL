const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
require('dotenv').config({ path: path.join(__dirname, '../.env.dev') });

const CONTAINER_NAME = process.env.MYSQL_CONTAINER_NAME || 'mysql';
const ROOT_PASSWORD = process.env.DB_ROOT_PASSWORD;

if (!ROOT_PASSWORD) {
  console.error('[에러] .env.dev에 DB_ROOT_PASSWORD가 없습니다.');
  process.exit(1);
}

function substitutePlaceholders(sqlContent, filePath) {
  const placeholderRegex = /<([A-Z0-9_]+)>/g;
  const missing = [];

  const result = sqlContent.replace(placeholderRegex, (match, key) => {
    const value = process.env[key];
    if (value === undefined) {
      missing.push(key);
      return match;
    }
    return value;
  });

  if (missing.length > 0) {
    console.error(
      `${filePath} 에서 .env.dev에 없는 값 발견: ${missing.join(', ')}`
    );
    process.exit(1);
  }

  return result;
}


function runSqlAgainstContainer(sqlContent, label) {
  console.log(`\n실행 중: ${label}`);

  const result = spawnSync(
    'docker',
    ['exec', '-i', CONTAINER_NAME, 'mysql', '-uroot', `-p${ROOT_PASSWORD}`],
    {
      input: sqlContent,
      stdio: ['pipe', 'inherit', 'inherit'],
    }
  );

  if (result.status !== 0) {
    console.error(`${label} 실행 중 에러 발생 (exit code ${result.status})`);
    process.exit(result.status || 1);
  }

  console.log(`완료: ${label}`);
}

const files = process.argv.slice(2);

if (files.length === 0) {
  console.error('사용법: node scripts/apply-sql.js <sql파일1> [sql파일2] ...');
  console.error('예시:   node scripts/apply-sql.js db/01_init.sql db/02_ml_schema.sql');
  process.exit(1);
}

for (const file of files) {
  const fullPath = path.resolve(file);

  if (!fs.existsSync(fullPath)) {
    console.error(`파일을 찾을 수 없습니다: ${fullPath}`);
    process.exit(1);
  }

  const rawSql = fs.readFileSync(fullPath, 'utf-8');
  const substitutedSql = substitutePlaceholders(rawSql, file);

  runSqlAgainstContainer(substitutedSql, file);
}

console.log('\n모든 SQL 파일 적용 완료.');