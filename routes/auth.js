const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const router = express.Router();

let users = [];
let refreshTokens = [];

router.post('/register', async (req,res)=>{
    const { username,password } = req.body;
    if (!username || username.length < 3 ) {
        return res.status(400).json({ message: 'Invalid username. Must be at least 3 characters long.' });
    }

    if (!password || password.length < 6 ) {
        return res.status(400).json({ message: 'Invalid password. Must be at least 6 characters long.' });
    }

    if(users.find(user => user.username === username)){
        return res.status(400).json({message:'User already exists'});
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    users.push({ username, password:hashedPassword});
    res.json({ message: 'User registered successfully' });
});

router.post('/login',async (req,res)=>{
    const { username,password  } = req.body;

    const user = users.find(u => u.username === username);
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }

    const accessToken = jwt.sign({username},process.env.JWT_SECRET,{ expiresIn: process.env.JWT_EXPIRES_IN });
    const refreshToken = jwt.sign({ username }, process.env.REFRESH_TOKEN_SECRET);
    refreshTokens.push(refreshToken);
    res.json({ accessToken, refreshToken });
});

router.post('/token',(req,res)=>{
    const { token } = req.body;
    if(!token || !refreshTokens.includes(token)){
        return res.status(403).json({ message: 'Forbidden' });
    }

    jwt.verify(token, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Forbidden' });
        const accessToken = jwt.sign({ username: user.username }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN });
        res.json({ accessToken });
    });
});

router.post('/logout', (req, res) => {
    const { token } = req.body;
    refreshTokens = refreshTokens.filter(t => t !== token);
    res.json({ message: 'Logged out successfully' });
});

module.exports = router;