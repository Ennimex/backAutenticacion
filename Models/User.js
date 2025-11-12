// Models/User.js
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: { 
    type: String, 
    required: true, 
    unique: true 
  },
  password: { 
    type: String, 
    required: true 
  },
  email: { 
    type: String, 
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  phone: { 
    type: String,
    sparse: true,
    unique: true
  },
  
  // ============================================
  // CONFIGURACIÓN MFA
  // ============================================
  mfaEnabled: { 
    type: Boolean, 
    default: false 
  },
  // Permite múltiples métodos seleccionados por el usuario
  mfaMethods: {
    type: [String],
    enum: ['email', 'app', 'sms'],
    default: []
  },
  
  // Para OTP por aplicación (Google Authenticator, Authy, etc.)
  otpSecret: { 
    type: String 
  },
  
  // Para almacenar OTP temporales (email y SMS)
  tempOTP: { 
    type: String 
  },
  otpExpiry: { 
    type: Date 
  },
  
  // Para recordar qué método eligió el usuario en este login
  selectedMfaMethod: { 
    type: String, 
    enum: ['email', 'app', 'sms'],
    default: null 
  },
  
  // Para controlar intentos fallidos de OTP
  otpAttempts: { 
    type: Number, 
    default: 0 
  },
  lastOtpAttempt: { 
    type: Date 
  },
  
  // ============================================
  // RECUPERACIÓN DE CONTRASEÑA
  // ============================================
  resetPasswordCode: {
    type: String,
    default: undefined
  },
  resetPasswordExpiry: {
    type: Date,
    default: undefined
  },
  resetPasswordAttempts: {
    type: Number,
    default: 0
  },
  
  // ============================================
  // ✅ DISPOSITIVOS CONFIABLES (NUEVO)
  // ============================================
  trustedDevices: [{
    deviceId: { 
      type: String, 
      required: true 
    },
    createdAt: { 
      type: Date, 
      default: Date.now 
    },
    expiresAt: { 
      type: Date, 
      required: true 
    }
  }]
}, {
  timestamps: true // Agrega createdAt y updatedAt automáticamente
});

// ============================================
// ÍNDICES PARA OPTIMIZACIÓN
// ============================================
userSchema.index({ email: 1 });
userSchema.index({ phone: 1 });
userSchema.index({ username: 1 });

// Índice TTL para auto-eliminar códigos expirados (opcional)
userSchema.index(
  { resetPasswordExpiry: 1 }, 
  { 
    expireAfterSeconds: 0,
    partialFilterExpression: { resetPasswordExpiry: { $exists: true } }
  }
);

// ✅ Índice para dispositivos confiables
userSchema.index({ 'trustedDevices.deviceId': 1 });
userSchema.index({ 'trustedDevices.expiresAt': 1 });

module.exports = mongoose.model('User', userSchema);