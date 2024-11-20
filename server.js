const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const { authenticator } = require('otplib');
const QRCode = require('qrcode');

const app = express();
app.use(bodyParser.json());

const users = {}; 
const SECRET_KEY = 'mi_clave_secreta'; 

authenticator.options = { step: 30, window: 1 }; 

app.listen(3000, () => {
  console.log('Servidor en funcionamiento en http://localhost:3000');
});

app.post('/register', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username y password son requeridos' });
    }

    if (users[username]) {
        return res.status(400).json({ message: 'Usuario ya registrado' });
    }

    const secret = authenticator.generateSecret();
    users[username] = { password, secret };

    const otpauth = authenticator.keyuri(username, 'MiAplicacion', secret);

    QRCode.toDataURL(otpauth, (err, imageUrl) => {
        if (err) {
            return res.status(500).json({ message: 'Error al generar el código QR' });
        }
        res.json({ message: 'Usuario registrado', qrCode: imageUrl });
    });
});

app.post('/login', (req, res) => {
    const { username, password, token } = req.body;

    const user = users[username];
    if (!user || user.password !== password) {
        return res.status(403).json({ message: 'Credenciales inválidas' });
    }

    console.log("Token proporcionado:", token);
    console.log("Clave secreta del usuario:", user.secret);

    const isValid = authenticator.check(token, user.secret);
    console.log("Resultado de la validación:", isValid);

    if (!isValid) {
        return res.status(403).json({ message: 'Código de autenticación incorrecto' });
    }

    const authToken = jwt.sign({ username }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ message: 'Login exitoso', authToken });
});

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ message: 'Token requerido' });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ message: 'Token inválido' });
        req.user = user;
        next();
    });
}

app.get('/protected', authenticateToken, (req, res) => {
    res.json({ message: `Hola, ${req.user.username}, tienes acceso a esta ruta protegida` });
});
