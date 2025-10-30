const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const User = require('../Models/User');
const { sendEmail, twilioClient } = require('../config/services'); // ✅ Cambio aquí
const { generateNumericOTP, generateAppSecret, verifyAppOTP } = require('../utils/otpUtils');

// ============================================
// REGISTRO DE USUARIO (Devuelve userId)
// ============================================
router.post('/register', async (req, res) => {
  try {
    const { username, password, email, phone } = req.body;
    
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: 'El usuario ya existe' });
    }
    
    const newUser = new User({ 
      username, 
      password,
      email,
      phone
    });
    
    await newUser.save();
    
    res.status(201).json({ 
      message: 'Usuario registrado exitosamente',
      userId: newUser._id,
      username: newUser.username
    });
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
    
    if (user.password !== password) {
      return res.status(401).json({ message: 'Contraseña o usuario incorrecto' });
    }
    
    // Si no tiene MFA habilitado
    if (!user.mfaEnabled || !user.mfaMethods || user.mfaMethods.length === 0) {
      const token = jwt.sign(
        { userId: user._id, username: user.username },
        process.env.JWT_SECRET,
        { expiresIn: '24h' }
      );
      
      return res.json({ 
        message: 'Inicio de sesión exitoso',
        token,
        requiresMFA: false
      });
    }
    
    res.json({ 
      message: 'Credenciales válidas. Selecciona un método de verificación',
      requiresMFA: true,
      mfaMethods: user.mfaMethods,
      userId: user._id
    });
    
  } catch (error) {
    res.status(500).json({ message: 'Error al iniciar sesión', error: error.message });
  }
});

// ============================================
// SOLICITAR OTP (Paso 2: Usuario elige método)
// ============================================
router.post('/request-otp', async (req, res) => {
  try {
    const { userId, method } = req.body;
    
    if (!method || !['email', 'sms', 'app'].includes(method)) {
      return res.status(400).json({ 
        message: 'Método inválido. Usa: email, sms o app' 
      });
    }
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    
    // Verificar que el método esté habilitado
    if (!user.mfaMethods || !user.mfaMethods.includes(method)) {
      return res.status(400).json({ 
        message: 'Este método MFA no está configurado para tu cuenta' 
      });
    }
    
    // Si es app, no se envía OTP (usa TOTP)
    if (method === 'app') {
      return res.json({ 
        message: 'Ingresa el código de tu aplicación autenticadora',
        method: 'app'
      });
    }
    
    // Generar y enviar OTP solo al método seleccionado
    const otp = generateNumericOTP();
    user.tempOTP = otp;
    user.otpExpiry = Date.now() + 10 * 60 * 1000;
    user.selectedMfaMethod = method;
    await user.save();
    
    // ✅ ENVÍO POR EMAIL CON BREVO
    if (method === 'email') {
      try {
        await sendEmail({
          to: user.email,
          subject: 'Código de verificación',
          html: `
            <h2>Código de verificación</h2>
            <p>Tu código de verificación es: <strong>${otp}</strong></p>
            <p>Este código expira en 10 minutos.</p>
          `
        });
        
        return res.json({ 
          message: `Código enviado a ${user.email.substring(0, 3)}***@***`,
          method: 'email'
        });
      } catch (emailError) {
        console.error('❌ ERROR AL ENVIAR EMAIL:', emailError);
        return res.status(500).json({ 
          message: 'No se pudo enviar el código por email. Intenta con otro método.',
          error: emailError.message
        });
      }
    }
    
    // ENVÍO POR SMS CON TWILIO
    if (method === 'sms') {
      try {
        await twilioClient.messages.create({
          body: `Tu código de verificación es: ${otp}. Válido por 10 minutos.`,
          from: process.env.TWILIO_PHONE_NUMBER,
          to: user.phone
        });
        
        const maskedPhone = user.phone.substring(0, 6) + '****';
        return res.json({ 
          message: `Código enviado a ${maskedPhone}`,
          method: 'sms'
        });
      } catch (smsError) {
        console.error('❌ ERROR AL ENVIAR SMS:', smsError);
        return res.status(500).json({ 
          message: 'No se pudo enviar el código por SMS',
          error: smsError.message
        });
      }
    }
    
  } catch (error) {
    console.error('ERROR EN REQUEST-OTP:', error);
    res.status(500).json({ 
      message: 'Error al procesar solicitud de OTP', 
      error: error.message 
    });
  }
});

// ============================================
// VERIFICAR OTP (Paso 3: Validar código)
// ============================================
router.post('/verify-otp', async (req, res) => {
  try {
    const { userId, otp, method } = req.body;
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    
    // Verificar rate limiting
    if (user.otpAttempts >= 5) {
      const timeSinceLastAttempt = Date.now() - (user.lastOtpAttempt || 0);
      if (timeSinceLastAttempt < 60000) {
        return res.status(429).json({ 
          message: 'Demasiados intentos fallidos. Intenta en 1 minuto' 
        });
      }
      user.otpAttempts = 0;
    }

    // Determinar método usado
    let methodUsed = method || user.selectedMfaMethod;
    if (!methodUsed && user.mfaMethods?.length === 1) {
      methodUsed = user.mfaMethods[0];
    }
    
    if (!methodUsed) {
      return res.status(400).json({ 
        message: 'Se requiere especificar el método MFA usado' 
      });
    }

    let isValid = false;

    // Verificar según el método
    if (methodUsed === 'app') {
      isValid = verifyAppOTP(user.otpSecret, otp);
    } else if (methodUsed === 'email' || methodUsed === 'sms') {
      if (!user.otpExpiry || Date.now() > user.otpExpiry) {
        return res.status(400).json({ message: 'El código ha expirado' });
      }
      isValid = user.tempOTP === otp;
    } else {
      return res.status(400).json({ message: 'Método MFA no soportado' });
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
    
    // OTP válido - limpiar y generar token
    user.otpAttempts = 0;
    user.tempOTP = undefined;
    user.otpExpiry = undefined;
    user.selectedMfaMethod = undefined;
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
    res.status(500).json({ 
      message: 'Error al verificar OTP', 
      error: error.message 
    });
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
    
    if (!user.email) {
      return res.status(400).json({ 
        message: 'Debes tener un email registrado para habilitar este método' 
      });
    }
    
    user.mfaEnabled = true;
    user.mfaMethods = user.mfaMethods || [];
    if (!user.mfaMethods.includes('email')) {
      user.mfaMethods.push('email');
    }
    await user.save();
    
    res.json({ 
      message: 'MFA por email habilitado exitosamente', 
      mfaMethods: user.mfaMethods 
    });
  } catch (error) {
    res.status(500).json({ 
      message: 'Error al habilitar MFA', 
      error: error.message 
    });
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
    
    if (!phone) {
      return res.status(400).json({ 
        message: 'Se requiere un número de teléfono' 
      });
    }
    
    user.phone = phone;
    user.mfaEnabled = true;
    user.mfaMethods = user.mfaMethods || [];
    if (!user.mfaMethods.includes('sms')) {
      user.mfaMethods.push('sms');
    }
    await user.save();
    
    res.json({ 
      message: 'MFA por SMS habilitado exitosamente', 
      mfaMethods: user.mfaMethods 
    });
  } catch (error) {
    res.status(500).json({ 
      message: 'Error al habilitar MFA', 
      error: error.message 
    });
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
    
    const { secret, qrCode } = await generateAppSecret(user.username);
    
    user.otpSecret = secret;
    user.mfaEnabled = true;
    user.mfaMethods = user.mfaMethods || [];
    if (!user.mfaMethods.includes('app')) {
      user.mfaMethods.push('app');
    }
    await user.save();
    
    res.json({ 
      message: 'Escanea este código QR con Google Authenticator o Authy',
      qrCode,
      secret,
      mfaMethods: user.mfaMethods
    });
  } catch (error) {
    res.status(500).json({ 
      message: 'Error al habilitar MFA', 
      error: error.message 
    });
  }
});

// ============================================
// OBTENER MÉTODOS MFA DEL USUARIO
// ============================================
router.get('/mfa-methods/:userId', async (req, res) => {
  try {
    const user = await User.findById(req.params.userId);
    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    
    res.json({ 
      mfaEnabled: user.mfaEnabled || false,
      mfaMethods: user.mfaMethods || [],
      hasEmail: !!user.email,
      hasPhone: !!user.phone
    });
  } catch (error) {
    res.status(500).json({ 
      message: 'Error al obtener métodos MFA', 
      error: error.message 
    });
  }
});

// ============================================
// DESHABILITAR UN MÉTODO MFA
// ============================================
router.post('/disable-mfa-method', async (req, res) => {
  try {
    const { userId, method } = req.body;
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    
    if (!user.mfaMethods || !user.mfaMethods.includes(method)) {
      return res.status(400).json({ 
        message: 'Este método no está habilitado' 
      });
    }
    
    user.mfaMethods = user.mfaMethods.filter(m => m !== method);
    
    // Si no quedan métodos, deshabilitar MFA completamente
    if (user.mfaMethods.length === 0) {
      user.mfaEnabled = false;
    }
    
    // Limpiar datos específicos del método
    if (method === 'app') {
      user.otpSecret = undefined;
    }
    
    await user.save();
    
    res.json({ 
      message: `MFA por ${method} deshabilitado exitosamente`,
      mfaMethods: user.mfaMethods,
      mfaEnabled: user.mfaEnabled
    });
  } catch (error) {
    res.status(500).json({ 
      message: 'Error al deshabilitar método MFA', 
      error: error.message 
    });
  }
});

module.exports = router;