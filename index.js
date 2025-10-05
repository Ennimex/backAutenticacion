const express = require('express');
const app = express();

app.use(express.json());

app.get('/', (req, res) => {
    res.send('¡Servidor funcionando correctamente!');
});

const authRoutes = require('./Routes/auth');
app.use('/api/auth', authRoutes);

module.exports = app;