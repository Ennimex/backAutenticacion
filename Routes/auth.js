const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const User = require('../Models/User');
const { sendEmail, twilioClient } = require('../config/services');
const { generateNumericOTP, generateAppSecret, verifyAppOTP } = require('../utils/otpUtils');

// ============================================
// REGISTRO DE USUARIO (Con validación de duplicados)
// ============================================
router.post('/register', async (req, res) => {
  try {
    const { username, password, email, phone } = req.body;
    
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ 
        message: 'El usuario ya existe',
        field: 'username' 
      });
    }
    
    if (email) {
      const existingEmail = await User.findOne({ email });
      if (existingEmail) {
        return res.status(400).json({ 
          message: 'Este correo electrónico ya está registrado',
          field: 'email'
        });
      }
    }
    
    if (phone) {
      const existingPhone = await User.findOne({ phone });
      if (existingPhone) {
        return res.status(400).json({ 
          message: 'Este número de teléfono ya está registrado',
          field: 'phone'
        });
      }
    }
    
    const newUser = new User({ 
      username, 
      password,
      email,
      phone,
      trustedDevices: [] // ✅ Inicializar array de dispositivos confiables
    });
    
    await newUser.save();
    
    res.status(201).json({ 
      message: 'Usuario registrado exitosamente',
      userId: newUser._id,
      username: newUser.username
    });
  } catch (error) {
    res.status(500).json({ 
      message: 'Error al registrar usuario', 
      error: error.message 
    });
  }
});

// ============================================
// VERIFICAR DISPONIBILIDAD DE DATOS
// ============================================
router.post('/check-availability', async (req, res) => {
  try {
    const { username, email, phone } = req.body;
    
    const response = {
      usernameAvailable: true,
      emailAvailable: true,
      phoneAvailable: true
    };
    
    if (username) {
      const existingUser = await User.findOne({ username });
      response.usernameAvailable = !existingUser;
    }
    
    if (email) {
      const existingEmail = await User.findOne({ email });
      response.emailAvailable = !existingEmail;
    }
    
    if (phone) {
      const existingPhone = await User.findOne({ phone });
      response.phoneAvailable = !existingPhone;
    }
    
    res.json(response);
  } catch (error) {
    res.status(500).json({ 
      message: 'Error al verificar disponibilidad', 
      error: error.message 
    });
  }
});

// ============================================
// 🆕 FUNCIÓN AUXILIAR: Verificar si el dispositivo es confiable
// ============================================
function isDeviceTrusted(user, deviceId) {
  if (!user.trustedDevices || !deviceId) return false;
  
  const device = user.trustedDevices.find(d => d.deviceId === deviceId);
  if (!device) return false;
  
  // Verificar si el dispositivo ha expirado (30 días)
  const expiryDate = new Date(device.expiresAt);
  return expiryDate > new Date();
}

// ============================================
// 🆕 FUNCIÓN AUXILIAR: Generar ID único de dispositivo
// ============================================
function generateDeviceId() {
  return crypto.randomBytes(32).toString('hex');
}

// ============================================
// INICIAR SESIÓN (✨ CON SOPORTE PARA RECORDAR DISPOSITIVO)
// ============================================
router.post('/login', async (req, res) => {
  try {
    const { username, password, deviceId } = req.body;
    
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ message: 'Contraseña o usuario incorrecto' });
    }
    
    if (user.password !== password) {
      return res.status(401).json({ message: 'Contraseña o usuario incorrecto' });
    }
    
    // ✅ SI NO TIENE MFA O SI EL DISPOSITIVO ES CONFIABLE
    const deviceIsTrusted = isDeviceTrusted(user, deviceId);
    
    if (!user.mfaEnabled || !user.mfaMethods || user.mfaMethods.length === 0 || deviceIsTrusted) {
      const token = jwt.sign(
        { userId: user._id, username: user.username },
        process.env.JWT_SECRET,
        { expiresIn: '24h' }
      );
      
      return res.json({ 
        message: 'Inicio de sesión exitoso',
        token,
        requiresMFA: false,
        deviceTrusted: deviceIsTrusted
      });
    }
    
    // ✅ SI TIENE MFA Y EL DISPOSITIVO NO ES CONFIABLE
    res.json({ 
      message: 'Credenciales válidas. Selecciona un método de verificación',
      requiresMFA: true,
      mfaMethods: user.mfaMethods,
      userId: user._id,
      email: user.email ? user.email.substring(0, 3) + '***@***' : undefined,
      phone: user.phone ? user.phone.substring(0, 6) + '****' : undefined
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
    
    if (!user.mfaMethods || !user.mfaMethods.includes(method)) {
      return res.status(400).json({ 
        message: 'Este método MFA no está configurado para tu cuenta' 
      });
    }
    
    if (method === 'app') {
      return res.json({ 
        message: 'Ingresa el código de tu aplicación autenticadora',
        method: 'app'
      });
    }
    
    const otp = generateNumericOTP();
    user.tempOTP = otp;
    user.otpExpiry = Date.now() + 10 * 60 * 1000;
    user.selectedMfaMethod = method;
    await user.save();
    
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
// VERIFICAR OTP (✨ CON OPCIÓN DE RECORDAR DISPOSITIVO)
// ============================================
router.post('/verify-otp', async (req, res) => {
  try {
    const { userId, otp, method, rememberDevice } = req.body;
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    
    if (user.otpAttempts >= 5) {
      const timeSinceLastAttempt = Date.now() - (user.lastOtpAttempt || 0);
      if (timeSinceLastAttempt < 60000) {
        return res.status(429).json({ 
          message: 'Demasiados intentos fallidos. Intenta en 1 minuto' 
        });
      }
      user.otpAttempts = 0;
    }

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
    
    // ✅ OTP VÁLIDO - LIMPIAR Y GENERAR TOKEN
    user.otpAttempts = 0;
    user.tempOTP = undefined;
    user.otpExpiry = undefined;
    user.selectedMfaMethod = undefined;
    
    // ✅ SI EL USUARIO QUIERE RECORDAR EL DISPOSITIVO
    let newDeviceId = null;
    if (rememberDevice) {
      newDeviceId = generateDeviceId();
      
      // Inicializar array si no existe
      if (!user.trustedDevices) {
        user.trustedDevices = [];
      }
      
      // Agregar dispositivo confiable (válido por 30 días)
      user.trustedDevices.push({
        deviceId: newDeviceId,
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // 30 días
      });
      
      // Limpiar dispositivos expirados (mantener solo los últimos 5)
      user.trustedDevices = user.trustedDevices
        .filter(d => new Date(d.expiresAt) > new Date())
        .slice(-5);
    }
    
    await user.save();
    
    const token = jwt.sign(
      { userId: user._id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.json({ 
      message: 'Autenticación exitosa',
      token,
      deviceId: newDeviceId // ⚠️ IMPORTANTE: Guardar esto en el cliente (localStorage)
    });
    
  } catch (error) {
    res.status(500).json({ 
      message: 'Error al verificar OTP', 
      error: error.message 
    });
  }
});

// ============================================
// 🆕 VER DISPOSITIVOS CONFIABLES
// ============================================
router.get('/trusted-devices/:userId', async (req, res) => {
  try {
    const user = await User.findById(req.params.userId);
    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    
    // Filtrar solo dispositivos activos
    const activeDevices = (user.trustedDevices || [])
      .filter(d => new Date(d.expiresAt) > new Date())
      .map(d => ({
        deviceId: d.deviceId.substring(0, 8) + '...', // Mostrar solo parte
        createdAt: d.createdAt,
        expiresAt: d.expiresAt
      }));
    
    res.json({ 
      devices: activeDevices,
      count: activeDevices.length
    });
  } catch (error) {
    res.status(500).json({ 
      message: 'Error al obtener dispositivos', 
      error: error.message 
    });
  }
});

// ============================================
// 🆕 ELIMINAR TODOS LOS DISPOSITIVOS CONFIABLES
// ============================================
router.post('/revoke-all-devices', async (req, res) => {
  try {
    const { userId } = req.body;
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    
    user.trustedDevices = [];
    await user.save();
    
    res.json({ 
      message: 'Todos los dispositivos confiables han sido revocados'
    });
  } catch (error) {
    res.status(500).json({ 
      message: 'Error al revocar dispositivos', 
      error: error.message 
    });
  }
});

// ============================================
// RECUPERACIÓN DE CONTRASEÑA - PASO 1: SOLICITAR CÓDIGO
// ============================================
router.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ 
        message: 'El correo electrónico es requerido' 
      });
    }
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ 
        message: 'Si el correo existe en nuestro sistema, recibirás un código de verificación' 
      });
    }
    
    const resetCode = generateNumericOTP();
    
    user.resetPasswordCode = resetCode;
    user.resetPasswordExpiry = Date.now() + 10 * 60 * 1000;
    user.resetPasswordAttempts = 0;
    await user.save();
    
    try {
      await sendEmail({
        to: user.email,
        subject: 'Recuperación de contraseña',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #667eea;">Recuperación de contraseña</h2>
            <p>Hola <strong>${user.username}</strong>,</p>
            <p>Recibimos una solicitud para restablecer tu contraseña.</p>
            <p>Tu código de verificación es:</p>
            <div style="background: #f0f0f0; padding: 20px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 5px; margin: 20px 0;">
              ${resetCode}
            </div>
            <p style="color: #666;">Este código expira en <strong>10 minutos</strong>.</p>
            <p style="color: #999; font-size: 12px;">Si no solicitaste este cambio, ignora este mensaje.</p>
          </div>
        `
      });
      
      console.log(`✅ Código de recuperación enviado a ${email}: ${resetCode}`);
      
      return res.json({ 
        message: 'Código de verificación enviado a tu correo electrónico'
      });
      
    } catch (emailError) {
      console.error('❌ ERROR AL ENVIAR EMAIL DE RECUPERACIÓN:', emailError);
      return res.status(500).json({ 
        message: 'No se pudo enviar el código. Por favor, intenta más tarde.',
        error: emailError.message
      });
    }
    
  } catch (error) {
    console.error('ERROR EN FORGOT-PASSWORD:', error);
    res.status(500).json({ 
      message: 'Error al procesar solicitud de recuperación', 
      error: error.message 
    });
  }
});

// ============================================
// RECUPERACIÓN DE CONTRASEÑA - PASO 2: VERIFICAR CÓDIGO
// ============================================
router.post('/verify-reset-code', async (req, res) => {
  try {
    const { email, code } = req.body;
    
    if (!email || !code) {
      return res.status(400).json({ 
        message: 'Email y código son requeridos' 
      });
    }
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ 
        message: 'Usuario no encontrado' 
      });
    }
    
    if (user.resetPasswordAttempts >= 5) {
      return res.status(429).json({ 
        message: 'Demasiados intentos fallidos. Solicita un nuevo código.' 
      });
    }
    
    if (!user.resetPasswordExpiry || Date.now() > user.resetPasswordExpiry) {
      return res.status(400).json({ 
        message: 'El código ha expirado. Solicita uno nuevo.' 
      });
    }
    
    if (user.resetPasswordCode !== code) {
      user.resetPasswordAttempts += 1;
      await user.save();
      
      return res.status(401).json({ 
        message: 'Código inválido',
        attemptsRemaining: 5 - user.resetPasswordAttempts
      });
    }
    
    const resetToken = jwt.sign(
      { 
        userId: user._id, 
        email: user.email,
        purpose: 'password-reset'
      },
      process.env.JWT_SECRET,
      { expiresIn: '15m' }
    );
    
    res.json({ 
      message: 'Código verificado exitosamente',
      token: resetToken
    });
    
  } catch (error) {
    console.error('ERROR EN VERIFY-RESET-CODE:', error);
    res.status(500).json({ 
      message: 'Error al verificar código', 
      error: error.message 
    });
  }
});

// ============================================
// RECUPERACIÓN DE CONTRASEÑA - PASO 3: RESTABLECER CONTRASEÑA
// ============================================
router.post('/reset-password', async (req, res) => {
  try {
    const { token, password, email } = req.body;
    
    if (!token || !password || !email) {
      return res.status(400).json({ 
        message: 'Token, email y nueva contraseña son requeridos' 
      });
    }
    
    if (password.length < 8) {
      return res.status(400).json({ 
        message: 'La contraseña debe tener al menos 8 caracteres' 
      });
    }
    
    if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(password)) {
      return res.status(400).json({ 
        message: 'La contraseña debe contener mayúscula, minúscula y número' 
      });
    }
    
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
      
      if (decoded.purpose !== 'password-reset') {
        return res.status(401).json({ 
          message: 'Token inválido para esta operación' 
        });
      }
      
      if (decoded.email !== email) {
        return res.status(401).json({ 
          message: 'Token no corresponde al email proporcionado' 
        });
      }
      
    } catch (jwtError) {
      return res.status(401).json({ 
        message: 'Token expirado o inválido. Solicita un nuevo código.' 
      });
    }
    
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(404).json({ 
        message: 'Usuario no encontrado' 
      });
    }
    
    user.password = password;
    user.resetPasswordCode = undefined;
    user.resetPasswordExpiry = undefined;
    user.resetPasswordAttempts = 0;
    // ✅ Limpiar dispositivos confiables al cambiar contraseña (seguridad)
    user.trustedDevices = [];
    await user.save();
    
    console.log(`✅ Contraseña restablecida para usuario: ${user.username}`);
    
    try {
      await sendEmail({
        to: user.email,
        subject: 'Contraseña actualizada',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #10b981;">Contraseña actualizada exitosamente</h2>
            <p>Hola <strong>${user.username}</strong>,</p>
            <p>Tu contraseña ha sido restablecida correctamente.</p>
            <p>Si no realizaste este cambio, contacta inmediatamente a soporte.</p>
          </div>
        `
      });
    } catch (emailError) {
      console.error('Error al enviar email de confirmación:', emailError);
    }
    
    res.json({ 
      message: 'Contraseña actualizada exitosamente' 
    });
    
  } catch (error) {
    console.error('ERROR EN RESET-PASSWORD:', error);
    res.status(500).json({ 
      message: 'Error al restablecer contraseña', 
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
    
    const existingPhone = await User.findOne({ 
      phone: phone, 
      _id: { $ne: user._id }
    });
    
    if (existingPhone) {
      return res.status(400).json({ 
        message: 'Este número de teléfono ya está registrado por otro usuario',
        field: 'phone'
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
    
    if (user.mfaMethods.length === 0) {
      user.mfaEnabled = false;
    }
    
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