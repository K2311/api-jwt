require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const authRoutes = require('./routes/auth');
const cookieParser = require('cookie-parser');

const app = express();
app.use(bodyParser.json());
app.use(cookieParser());
app.use('/auth',authRoutes);

const PORT = 3000;
app.listen(PORT,()=>{
    console.log(`Server running on http://localhost:${PORT}`);
});