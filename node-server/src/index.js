const path = require('path');
const dotenv = require('dotenv');
<<<<<<< HEAD
dotenv.config({ 
  path: path.join(__dirname, '../.env.dev')
=======

dotenv.config({
  path: path.join(__dirname, '../../.env.dev')
>>>>>>> 515b3667eaf577f7a0731a3486e2d295e665ee8d
});

console.log('RP_ID:', process.env.RP_ID);
console.log('ORIGIN:', process.env.ORIGIN);

const app = require('./app');

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`서버 실행 중: http://localhost:${PORT}`);
});