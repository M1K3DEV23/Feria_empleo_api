const jwt = require('jsonwebtoken');
const SECRET_KEY = require('./secret');

function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if(!authHeader) {
    res.status(401).json({ error: 'No se proporcionó un token de autenticación' });
  }

  const token = authHeader.split(' ')[1];

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Token inválido' });
    }

    req.userId = decoded.userId;
    next();
  });
}

module.exports = verifyToken;