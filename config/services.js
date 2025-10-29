const nodemailer = require('nodemailer');
const twilio = require('twilio');

const emailTransporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465, 
    secure: true, // Debe ser 'true' para el puerto 465 (TLS implícito)
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD // Esto ya es la App Password, ¡correcto!
    }
});

// Configuración de Twilio para SMS
const twilioClient = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);

module.exports = { emailTransporter, twilioClient };