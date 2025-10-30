const nodemailer = require('nodemailer');
const twilio = require('twilio');
const brevo = require('@getbrevo/brevo');

// Configuración de Brevo (API, no SMTP)
const brevoClient = new brevo.TransactionalEmailsApi();
brevoClient.setApiKey(
  brevo.TransactionalEmailsApiApiKeys.apiKey,
  process.env.BREVO_API_KEY
);

// Función helper para enviar emails con Brevo
async function sendEmailBrevo({ to, subject, html }) {
  const sendSmtpEmail = new brevo.SendSmtpEmail();
  
  sendSmtpEmail.subject = subject;
  sendSmtpEmail.htmlContent = html;
  sendSmtpEmail.sender = { 
    name: "Sistema MFA", 
    email: process.env.BREVO_SENDER_EMAIL 
  };
  sendSmtpEmail.to = [{ email: to }];
  
  return await brevoClient.sendTransacEmail(sendSmtpEmail);
}

// Configuración de Twilio para SMS
const twilioClient = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);

module.exports = { 
  sendEmailBrevo, 
  twilioClient 
};