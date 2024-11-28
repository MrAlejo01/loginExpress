require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const session = require('express-session');
const bcrypt = require('bcrypt');
const MySQLStore = require('express-mysql-session')(session);

const app = express();
const port = process.env.PORT || 3000;

// Configuración de middleware
app.use(cors({
  origin: "http://localhost:5173", // Asegúrate de que coincida con la URL del frontend
  credentials: true,
}));
app.use(express.json()); // Para manejar JSON en solicitudes

// Configuración de la base de datos
const connection = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'login',
});

// Configuración de almacenamiento de sesiones en la base de datos
const sessionStore = new MySQLStore({}, connection);

app.use(session({
  key: 'session_cookie_name',
  secret: process.env.SESSION_SECRET || 'clave_secreta',
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false, // Cambiar a true si usas HTTPS
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 1 día
  },
}));

// Middleware para proteger rutas
function isAuthenticated(req, res, next) {
  if (req.session.usuario) {
    next();
  } else {
    res.status(401).json({ error: "No autorizado" });
  }
}

// Ruta principal
app.get('/', (req, res) => {
  res.send('¡Servidor funcionando correctamente!');
});

// Ruta de inicio de sesión
app.post('/login', async (req, res) => {
  const { usuario, clave } = req.body;

  if (!usuario || !clave) {
    return res.status(400).json({ error: "Usuario y clave son obligatorios" });
  }

  try {
    const [results] = await connection.query(
      "SELECT * FROM `usuarios` WHERE `usuario` = ?",
      [usuario]
    );

    if (results.length > 0) {
      const match = await bcrypt.compare(clave, results[0].clave);
      if (match) {
        req.session.usuario = { id: results[0].id, usuario };
        res.status(200).json({ message: "Inicio de sesión correcto" });
      } else {
        res.status(401).json({ error: "Credenciales incorrectas" });
      }
    } else {
      res.status(401).json({ error: "Usuario no encontrado" });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error en el servidor" });
  }
});

// Ruta para validar sesión
app.get('/validar', isAuthenticated, (req, res) => {
  res.status(200).json({ message: "Sesión válida", usuario: req.session.usuario });
});

// Ruta para cerrar sesión
app.post('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error(err);
      res.status(500).json({ error: "Error al cerrar sesión" });
    } else {
      res.clearCookie('session_cookie_name');
      res.status(200).json({ message: "Sesión cerrada correctamente" });
    }
  });
});

// Ruta de registro de usuarios (opcional)
app.post('/register', async (req, res) => {
  const { usuario, clave } = req.body;

  if (!usuario || !clave) {
    return res.status(400).json({ error: "Usuario y clave son obligatorios" });
  }

  try {
    const hashedPassword = await bcrypt.hash(clave, 10);
    await connection.query(
      "INSERT INTO `usuarios` (`usuario`, `clave`) VALUES (?, ?)",
      [usuario, hashedPassword]
    );
    res.status(201).json({ message: "Usuario registrado exitosamente" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error en el servidor" });
  }
});

// Servidor escuchando
app.listen(port, () => {
  console.log(`Servidor escuchando en http://localhost:${port}`);
});
