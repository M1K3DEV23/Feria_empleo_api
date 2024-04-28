const crypto = require('crypto');

const generateSecretKey = () => {
  const secretKey = crypto.randomBytes(32).toString('hex');
  return secretKey;
}

const SECRET_KEY = generateSecretKey();

module.exports = SECRET_KEY;