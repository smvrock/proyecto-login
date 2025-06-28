require('dotenv').config(); // Carga las variables de entorno desde .env
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const port = 3000;

app.use(cors()); 
app.use(express.json()); 

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'miliana1',
    database: 'mi_aplicacion'
}).promise();

// --- Middleware para autenticar el Token ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Formato: Bearer TOKEN

    if (token == null) return res.sendStatus(401); // No hay token, no autorizado

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403); // Token inválido o expirado
        req.user = user;
        next(); // El token es válido, continuar
    });
};

// --- Rutas Públicas ---
app.post('/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password) {
            return res.status(400).json({ message: 'Por favor, completa todos los campos.' });
        }
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const query = 'INSERT INTO usuarios (nombre, email, password) VALUES (?, ?, ?)';
        await db.query(query, [name, email, hashedPassword]);
        res.status(201).json({ message: 'Usuario registrado con éxito.' });
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ message: 'El correo electrónico ya está registrado.' });
        }
        console.error('Error en el registro:', error);
        res.status(500).json({ message: 'Error en el servidor.' });
    }
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ message: 'Por favor, completa todos los campos.' });
        }
        const query = 'SELECT * FROM usuarios WHERE email = ?';
        const [rows] = await db.query(query, [email]);
        if (rows.length === 0) {
            return res.status(401).json({ message: 'Credenciales inválidas.' });
        }
        const user = rows[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Credenciales inválidas.' });
        }
        // Crear el token si las credenciales son correctas
        const accessToken = jwt.sign({ id: user.id, name: user.nombre }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token: accessToken });

    } catch (error) {
        console.error('Error en el inicio de sesión:', error);
        res.status(500).json({ message: 'Error en el servidor.' });
    }
});

// --- Rutas Protegidas ---
app.get('/api/profile', authenticateToken, async (req, res) => {
    // req.user es el payload del token que hemos añadido en el middleware
    // Ya sabemos que el usuario está autenticado.
    try {
        const query = 'SELECT id, nombre, email FROM usuarios WHERE id = ?';
        const [rows] = await db.query(query, [req.user.id]);
        if (rows.length === 0) {
            return res.status(404).json({ message: 'Usuario no encontrado.' });
        }
        res.json(rows[0]);
    } catch (error) {
        console.error('Error al obtener el perfil:', error);
        res.status(500).json({ message: 'Error en el servidor.' });
    }
});


app.listen(port, () => {
    console.log(`Servidor escuchando en http://localhost:${port}`);
});
