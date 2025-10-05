const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

// Generar código OTP de 6 dígitos
function generateNumericOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Generar secret para app authenticator
async function generateAppSecret(username) {
  const secret = speakeasy.generateSecret({
    name: `TuApp (${username})`,
    length: 32
  });
  
  const qrCode = await QRCode.toDataURL(secret.otpauth_url);
  
  return {
    secret: secret.base32,
    qrCode: qrCode
  };
}

// Verificar OTP de aplicación
function verifyAppOTP(secret, token) {
  return speakeasy.totp.verify({
    secret: secret,
    encoding: 'base32',
    token: token,
    window: 2 // Permite 2 pasos de tiempo de diferencia (60 segundos)
  });
}

module.exports = {
  generateNumericOTP,
  generateAppSecret,
  verifyAppOTP
};
