const path = require('path');
const dotenv = require('dotenv');

dotenv.config({
  path: path.join(__dirname, '../../.env.dev')
});

console.log('RP_ID:', process.env.RP_ID);
console.log('ORIGIN:', process.env.ORIGIN);

const app = require('./app');

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`서버 실행 중: http://localhost:${PORT}`);
});