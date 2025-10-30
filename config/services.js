const nodemailer = require('nodemailer');
const twilio = require('twilio');

// Configuración de Email con puerto 465 (SSL)
const emailTransporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 465,
  secure: true, // true para puerto 465
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD
  },
  // Timeouts para evitar bloqueos largos
  connectionTimeout: 10000, // 10 segundos
  greetingTimeout: 10000,
  socketTimeout: 10000,
  // Registrar errores de conexión
  logger: true,
  debug: false
});

// Verificar la conexión al iniciar (opcional pero recomendado)
emailTransporter.verify(function(error, success) {
  if (error) {
    console.error('❌ Error en configuración de email:', error.message);
  } else {
    console.log('✅ Servidor de email listo para enviar mensajes');
  }
});

// Configuración de Twilio para SMS
const twilioClient = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);

module.exports = { emailTransporter, twilioClient };