require('dotenv').config();
const app = require('../index');
const connectDB = require('./db');
// Conectar a la base de datos
connectDB();


const PORT = process.env.PORT ?? 3000;
app.listen(PORT, () => console.log(`🚀 Servidor corriendo en puerto ${PORT}`));
