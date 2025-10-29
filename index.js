require('dotenv').config();
const cors = require('cors');
const express = require('express');
const app = express();

// Configuración de CORS más específica
app.use(cors({
  origin: 'http://localhost:5173', // Puerto por defecto de Vite/Vue
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

app.use('/api/auth', authRoutes);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Servidor corriendo en puerto ${PORT}`));