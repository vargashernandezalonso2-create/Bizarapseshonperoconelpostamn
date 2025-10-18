require('dotenv').config()
const express = require('express')
const session = require('express-session')
const MySQLStore = require('express-mysql-session')(session)
const mysql = require('mysql2/promise')
const bcrypt = require('bcrypt')

const app = express()
app.use(express.json())

// Configuración del pool de MySQL
const pool = mysql.createPool({
  host: process.env.MYSQL_HOST,
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DATABASE,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
})

// Configuración del store de sesiones
const sessionStore = new MySQLStore({
  clearExpired: true,
  checkExpirationInterval: 900000, // 15 minutos
  expiration: 86400000, // 24 horas
}, pool)

// Configuración de sesiones
app.use(session({
  key: 'sid',
  secret: process.env.SESSION_SECRET,
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24, // 24 horas
    httpOnly: true,
    secure: false, // cambiar a true en producción con HTTPS
    sameSite: 'lax'
  }
}))

// ==================== RUTAS ====================

// Ruta de prueba
app.get('/', (req, res) => {
  res.json({ 
    mensaje: 'API de Sesiones funcionando',
    sesionActiva: !!req.session.userId
  })
})

// LOGIN
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body

    if (!username || !password) {
      return res.status(400).json({ mensaje: 'Faltan datos' })
    }

    // Buscar usuario en la base de datos
    const [rows] = await pool.query(
      'SELECT * FROM usuarios WHERE username = ?',
      [username]
    )

    if (rows.length === 0) {
      return res.status(401).json({ mensaje: 'Usuario o contraseña incorrecta' })
    }

    const user = rows[0]

    // Verificar contraseña
    const passwordValida = await bcrypt.compare(password, user.password)
    
    if (!passwordValida) {
      return res.status(401).json({ mensaje: 'Usuario o contraseña incorrecta' })
    }

    // Crear sesión
    req.session.userId = user.id
    req.session.username = user.username
    req.session.email = user.email

    res.json({ 
      mensaje: 'Has iniciado sesión correctamente',
      usuario: {
        id: user.id,
        username: user.username,
        email: user.email
      }
    })

  } catch (error) {
    console.error('Error en login:', error)
    res.status(500).json({ mensaje: 'Error del servidor' })
  }
})

// REGISTRO
app.post('/registro', async (req, res) => {
  try {
    const { username, password, email } = req.body

    if (!username || !password) {
      return res.status(400).json({ mensaje: 'Faltan datos' })
    }

    // Verificar si el usuario ya existe
    const [existing] = await pool.query(
      'SELECT id FROM usuarios WHERE username = ?',
      [username]
    )

    if (existing.length > 0) {
      return res.status(400).json({ mensaje: 'El usuario ya existe' })
    }

    // Encriptar contraseña
    const hashedPassword = await bcrypt.hash(password, 10)

    // Insertar usuario
    const [result] = await pool.query(
      'INSERT INTO usuarios (username, password, email) VALUES (?, ?, ?)',
      [username, hashedPassword, email]
    )

    res.status(201).json({ 
      mensaje: 'Usuario registrado correctamente',
      userId: result.insertId 
    })

  } catch (error) {
    console.error('Error en registro:', error)
    res.status(500).json({ mensaje: 'Error del servidor' })
  }
})

// LOGOUT
app.post('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).json({ mensaje: 'Error al cerrar sesión' })
    }
    res.clearCookie('sid')
    res.json({ mensaje: 'Has cerrado sesión' })
  })
})

// Middleware de autenticación
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) {
    return next()
  }
  res.status(401).json({ mensaje: 'No autorizado' })
}

// PERFIL (ruta protegida)
app.get('/perfil', requireAuth, (req, res) => {
  res.json({ 
    id: req.session.userId, 
    usuario: req.session.username,
    email: req.session.email
  })
})

// VERIFICAR SESIÓN
app.get('/verificar-sesion', (req, res) => {
  if (req.session && req.session.userId) {
    res.json({ 
      autenticado: true,
      usuario: {
        id: req.session.userId,
        username: req.session.username,
        email: req.session.email
      }
    })
  } else {
    res.json({ autenticado: false })
  }
})

// Iniciar servidor
const port = process.env.PORT || 3000
app.listen(port, () => {
  console.log(`✅ Servidor corriendo en http://localhost:${port}`)
})