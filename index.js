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

const authRoutes = require('./Routes/auth');
app.use('/api/auth', authRoutes);

module.exports = app;