const twilio = require('twilio');
const brevo = require('@getbrevo/brevo');

// ============================================
// CONFIGURACIÓN DE BREVO (Email via API)
// ============================================
const brevoClient = new brevo.TransactionalEmailsApi();
brevoClient.setApiKey(
  brevo.TransactionalEmailsApiApiKeys.apiKey,
  process.env.BREVO_API_KEY
);

// Función helper para enviar emails con Brevo
async function sendEmail({ to, subject, html }) {
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

// ============================================
// CONFIGURACIÓN DE TWILIO (SMS)
// ============================================
const twilioClient = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);

// ⚠️ IMPORTANTE: Exportar sendEmail, NO emailTransporter
module.exports = { 
  sendEmail,      // ✅ Función de Brevo
  twilioClient    // ✅ Cliente de Twilio
};