require('dotenv').config();
const cors = require('cors');
const express = require('express');
const app = express();

// ✅ Configuración de CORS dinámica
const allowedOrigins = [
  'http://localhost:5173',              // Desarrollo local
  'https://front-phi-teal.vercel.app'   // Producción (Vercel)
];

app.use(cors({
  origin: function (origin, callback) {
    // Permitir peticiones sin origin (por ejemplo, Postman o curl)
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    } else {
      console.log('❌ Bloqueado por CORS:', origin);
      return callback(new Error('No permitido por CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

app.get('/', (req, res) => {
  res.send('¡Servidor funcionando correctamente!');
});

const connectDB = require('./config/db');
const authRoutes = require('./Routes/auth');

// Conectar a la base de datos
connectDB();

// Rutas
app.use('/api/auth', authRoutes);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Servidor corriendo en puerto ${PORT}`));
