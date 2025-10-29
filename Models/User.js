const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  email: { type: String, required: true },
  phone: { type: String }, // Para SMS
  
  // Configuración MFA
  mfaEnabled: { type: Boolean, default: false },
  // Permite múltiples métodos seleccionados por el usuario
  mfaMethods: {
    type: [String],
    enum: ['email', 'app', 'sms'],
    default: []
  },
  
  // Para OTP por aplicación (Google Authenticator, Authy, etc.)
  otpSecret: { type: String },
  
  // Para almacenar OTP temporales (email y SMS)
  tempOTP: { type: String },
  otpExpiry: { type: Date },
  
  // ✨ NUEVO: Para recordar qué método eligió el usuario en este login
  selectedMfaMethod: { 
    type: String, 
    enum: ['email', 'app', 'sms'],
    default: null 
  },
  
  // Para controlar intentos fallidos
  otpAttempts: { type: Number, default: 0 },
  lastOtpAttempt: { type: Date }
});

module.exports = mongoose.model('User', userSchema);