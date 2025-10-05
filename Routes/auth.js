const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const User = require('../Models/User');
const { emailTransporter, twilioClient } = require('../config/services');
const { generateNumericOTP, generateAppSecret, verifyAppOTP } = require('../utils/otpUtils');

// ============================================
// REGISTRO DE USUARIO (Sin encriptación)
// ============================================
router.post('/register', async (req, res) => {
  try {
    const { username, password, email, phone } = req.body;
    
    // Verificar si el usuario ya existe
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: 'El usuario ya existe' });
    }
    
    const newUser = new User({ 
      username, 
      password, // Sin hash
      email,
      phone
    });
    
    await newUser.save();
    res.status(201).json({ message: 'Usuario registrado exitosamente' });
  } catch (error) {
    res.status(500).json({ message: 'Error al registrar usuario', error: error.message });
  }
});

// ============================================
// INICIAR SESIÓN (Paso 1: Validar credenciales)
// ============================================
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ message: 'Contraseña o usuario incorrecto' });
    }
    
    // Verificar contraseña (comparación directa)
    if (user.password !== password) {
      return res.status(401).json({ message: 'Contraseña o usuario incorrecto' });
    }
    
    // Si no tiene MFA habilitado, generar token directamente
    if (!user.mfaEnabled || user.mfaMethod === 'none') {
      const token = jwt.sign(
        { userId: user._id, username: user.username },
        process.env.JWT_SECRET,
        { expiresIn: '24h' }
      );
      
      return res.json({ 
        message: 'Login exitoso',
        token,
        requiresMFA: false
      });
    }
    
    // Si tiene MFA, enviar OTP según el método
    if (user.mfaMethod === 'email') {
      await sendEmailOTP(user);
    } else if (user.mfaMethod === 'sms') {
      await sendSMSOTP(user);
    }
    
    res.json({ 
      message: 'Credenciales válidas. Ingresa el código OTP',
      requiresMFA: true,
      mfaMethod: user.mfaMethod,
      userId: user._id // Solo para identificar en el siguiente paso
    });
    
  } catch (error) {
    res.status(500).json({ message: 'Error al iniciar sesión', error: error.message });
  }
});

// ============================================
// VERIFICAR OTP (Paso 2: Validar código)
// ============================================
router.post('/verify-otp', async (req, res) => {
  try {
    const { userId, otp } = req.body;
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    
    // Verificar intentos fallidos
    if (user.otpAttempts >= 5) {
      const timeSinceLastAttempt = Date.now() - user.lastOtpAttempt;
      if (timeSinceLastAttempt < 15 * 60 * 1000) { // 15 minutos
        return res.status(429).json({ 
          message: 'Demasiados intentos fallidos. Intenta en 15 minutos' 
        });
      }
      user.otpAttempts = 0;
    }
    
    let isValid = false;
    
    // Verificar según el método
    if (user.mfaMethod === 'app') {
      isValid = verifyAppOTP(user.otpSecret, otp);
    } else if (user.mfaMethod === 'email' || user.mfaMethod === 'sms') {
      // Verificar expiración
      if (Date.now() > user.otpExpiry) {
        return res.status(400).json({ message: 'El código ha expirado' });
      }
      isValid = user.tempOTP === otp;
    }
    
    if (!isValid) {
      user.otpAttempts += 1;
      user.lastOtpAttempt = Date.now();
      await user.save();
      
      return res.status(401).json({ 
        message: 'Código OTP inválido',
        attemptsRemaining: 5 - user.otpAttempts
      });
    }
    
    // OTP válido - generar token JWT
    user.otpAttempts = 0;
    user.tempOTP = undefined;
    user.otpExpiry = undefined;
    await user.save();
    
    const token = jwt.sign(
      { userId: user._id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.json({ 
      message: 'Autenticación exitosa',
      token
    });
    
  } catch (error) {
    res.status(500).json({ message: 'Error al verificar OTP', error: error.message });
  }
});

// ============================================
// HABILITAR MFA POR EMAIL
// ============================================
router.post('/enable-mfa-email', async (req, res) => {
  try {
    const { userId } = req.body;
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    
    user.mfaEnabled = true;
    user.mfaMethod = 'email';
    await user.save();
    
    res.json({ message: 'MFA por email habilitado exitosamente' });
  } catch (error) {
    res.status(500).json({ message: 'Error al habilitar MFA', error: error.message });
  }
});

// ============================================
// HABILITAR MFA POR SMS
// ============================================
router.post('/enable-mfa-sms', async (req, res) => {
  try {
    const { userId, phone } = req.body;
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    
    user.phone = phone;
    user.mfaEnabled = true;
    user.mfaMethod = 'sms';
    await user.save();
    
    res.json({ message: 'MFA por SMS habilitado exitosamente' });
  } catch (error) {
    res.status(500).json({ message: 'Error al habilitar MFA', error: error.message });
  }
});

// ============================================
// HABILITAR MFA POR APLICACIÓN
// ============================================
router.post('/enable-mfa-app', async (req, res) => {
  try {
    const { userId } = req.body;
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    
    // Generar secret y QR code
    const { secret, qrCode } = await generateAppSecret(user.username);
    
    user.otpSecret = secret;
    user.mfaEnabled = true;
    user.mfaMethod = 'app';
    await user.save();
    
    res.json({ 
      message: 'Escanea este código QR con Google Authenticator o Authy',
      qrCode,
      secret // Por si quieren ingresarlo manualmente
    });
  } catch (error) {
    res.status(500).json({ message: 'Error al habilitar MFA', error: error.message });
  }
});

// ============================================
// FUNCIONES AUXILIARES
// ============================================

// Enviar OTP por Email
async function sendEmailOTP(user) {
  const otp = generateNumericOTP();
  
  user.tempOTP = otp;
  user.otpExpiry = Date.now() + 10 * 60 * 1000; // 10 minutos
  await user.save();
  
  await emailTransporter.sendMail({
    from: process.env.EMAIL_USER,
    to: user.email,
    subject: 'Código de verificación',
    html: `
      <h2>Código de verificación</h2>
      <p>Tu código de verificación es: <strong>${otp}</strong></p>
      <p>Este código expira en 10 minutos.</p>
    `
  });
}

// Enviar OTP por SMS
async function sendSMSOTP(user) {
  const otp = generateNumericOTP();
  
  user.tempOTP = otp;
  user.otpExpiry = Date.now() + 10 * 60 * 1000; // 10 minutos
  await user.save();
  
  await twilioClient.messages.create({
    body: `Tu código de verificación es: ${otp}. Válido por 10 minutos.`,
    from: process.env.TWILIO_PHONE_NUMBER,
    to: user.phone
  });
}

module.exports = router;