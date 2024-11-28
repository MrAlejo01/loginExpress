require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const session = require('express-session');
const bcrypt = require('bcrypt');

const app = express();
const port = process.env.PORT || 3000;

// Configuración de middleware
app.use(cors({
  origin: "http://localhost:5173",
  credentials: true,
}));
app.use(express.json()); // Para manejar JSON en solicitudes
app.use(session({
  secret: process.env.SESSION_SECRET || "clave_secreta",
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false }, // Cambiar a true si usas HTTPS
}));

// Configuración de la base de datos
const connection = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'login',
});

// Middleware para proteger rutas
function isAuthenticated(req, res, next) {
  if (req.session.usuario) {
    next();
  } else {
    res.status(401).send("No autorizado");
  }
}

// Ruta principal
app.get('/', (req, res) => {
  res.send('¡Servidor funcionando correctamente!');
});

// Ruta de inicio de sesión
app.post('/login', async (req, res) => {
  const { usuario, clave } = req.body;

  try {
    const [results] = await connection.query(
      "SELECT * FROM `usuarios` WHERE `usuario` = ?",
      [usuario]
    );

    if (results.length > 0) {
      const match = await bcrypt.compare(clave, results[0].clave);
      if (match) {
        req.session.usuario = usuario;
        res.status(200).send("Inicio de sesión correcto");
      } else {
        res.status(401).send("Credenciales incorrectas");
      }
    } else {
      res.status(401).send("Usuario no encontrado");
    }
  } catch (err) {
    console.error(err);
    res.status(500).send("Error en el servidor");
  }
});

// Ruta para validar sesión
app.get('/validar', isAuthenticated, (req, res) => {
  res.status(200).send("Sesión validada");
});

// Ruta para cerrar sesión
app.post('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error(err);
      res.status(500).send("Error al cerrar sesión");
    } else {
      res.status(200).send("Sesión cerrada correctamente");
    }
  });
});

// Servidor escuchando
app.listen(port, () => {
  console.log(`Servidor escuchando en http://localhost:${port}`);
});