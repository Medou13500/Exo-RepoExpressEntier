const express = require('express');
const argon2 = require('argon2'); // Importer argon2
const jwt = require('jsonwebtoken'); // Importer jsonwebtoken
require('dotenv').config(); // Charger les variables d'environnement depuis le fichier .env

const app = express();
app.use(express.json());
let port = 1000;

let users = [
    {
        id: 1,
        name: "mehdy",
        surname: "Bouzid",
        age: 22,
        email: "mehdybouzid13500@gmail.com",
        password: "examplepassword" // Ceci est un exemple; le mot de passe devrait être haché.
    }
];

// Fonction pour vérifier le format de l'email
function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(String(email).toLowerCase());
}

// Fonction asynchrone pour hasher un mot de passe
async function hashPassword(password) {
    try {
        const hashedPassword = await argon2.hash(password, {
            type: argon2.argon2id, // Type d'algorithme
            memoryCost: 2 ** 16, // Coût en mémoire
            timeCost: 5, // Coût en temps
            parallelism: 1 // Degré de parallélisme
        });
        return hashedPassword;
    } catch (err) {
        throw new Error('Error hashing password');
    }
}

// Middleware pour authentifier le token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.status(401).send('Access Denied: No Token Provided');

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).send('Access Denied: Invalid Token');
        req.user = user;
        next();
    });
}

app.get('/', (req, res) => {
    res.send('bienvenue dans mon centre entrainement backend');
});

app.get('/user', authenticateToken, (req, res) => {
    res.json(users);
});

app.post('/user', async (req, res) => {
    const newUser = req.body;
    const newUserId = users.length + 1;

    if (!validateEmail(newUser.email)) {
        return res.status(400).send('Invalid email format');
    }

    try {
        const hashedPassword = await hashPassword(newUser.password);

        const userWithId = {
            id: newUserId,
            name: newUser.name,
            surname: newUser.surname,
            age: newUser.age,
            email: newUser.email,
            password: hashedPassword
        };

        users.push(userWithId);
        res.status(201).send('User is created');
    } catch (error) {
        res.status(500).send('Error creating user');
    }
});

app.post("/login", async (req, res) => {
    const { email } = req.body;

    if (!validateEmail(email)) {
        return res.status(400).send('Invalid email format');
    }

    const user = users.find(user => user.email === email);
    if (user) {
        const token = jwt.sign(
            { id: user.id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );
        res.json({ message: 'Login successful', token });
    } else {
        res.status(404).send('User not found');
    }
});

app.put('/user/:id', authenticateToken, async (req, res) => {
    const userId = parseInt(req.params.id);
    const updateUser = req.body;
    const user = users.find(user => user.id === userId);

    if (user) {
        if (updateUser.name) user.name = updateUser.name;
        if (updateUser.age) user.age = updateUser.age;
        if (updateUser.surname) user.surname = updateUser.surname;
        if (updateUser.email) user.email = updateUser.email;
        if (updateUser.password) {
            try {
                user.password = await hashPassword(updateUser.password);
            } catch (error) {
                return res.status(500).send('Error updating password');
            }
        }
        res.send(`User with id ${userId} updated`);
    } else {
        res.status(404).send('User not found');
    }
});

app.delete('/user/:id', authenticateToken, (req, res) => {
    const userId = parseInt(req.params.id);
    const userIndex = users.findIndex(user => user.id === userId);

    if (userIndex !== -1) {
        users.splice(userIndex, 1);
        res.send(`User with id ${userId} deleted`);
    } else {
        res.status(404).send('User not found');
    }
});

app.listen(port, () => {
    console.log(`server listening http://localhost:${port}`);
});
