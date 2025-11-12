// Models/User.js - VERSIÓN CORREGIDA
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
  
  // CONFIGURACIÓN MFA
  mfaEnabled: { 
    type: Boolean, 
    default: false 
  },
  mfaMethods: {
    type: [String],
    enum: ['email', 'app', 'sms'],
    default: []
  },
  otpSecret: { 
    type: String 
  },
  tempOTP: { 
    type: String 
  },
  otpExpiry: { 
    type: Date 
  },
  selectedMfaMethod: { 
    type: String, 
    enum: ['email', 'app', 'sms'],
    default: null 
  },
  otpAttempts: { 
    type: Number, 
    default: 0 
  },
  lastOtpAttempt: { 
    type: Date 
  },
  
  // RECUPERACIÓN DE CONTRASEÑA
  resetPasswordCode: {
    type: String
  },
  resetPasswordExpiry: {
    type: Date
  },
  resetPasswordAttempts: {
    type: Number,
    default: 0
  },
  
  // DISPOSITIVOS CONFIABLES
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
  timestamps: true
});

// Solo índices especiales (no duplicados)
userSchema.index(
  { resetPasswordExpiry: 1 }, 
  { 
    expireAfterSeconds: 0,
    partialFilterExpression: { resetPasswordExpiry: { $exists: true } }
  }
);

userSchema.index({ 'trustedDevices.expiresAt': 1 });

module.exports = mongoose.model('User', userSchema);