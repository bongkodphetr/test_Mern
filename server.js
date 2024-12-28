const express = require('express');
const connectDB = require('./config/db');
require('dotenv').config();

const app = express();

// เชื่อมต่อฐานข้อมูล
connectDB();

// Middleware
app.use(express.json());

// Routes
app.use('/api/auth', require('./routes/auth'));

const PORT = process.env.PORT || 4000;

app.listen(PORT, () => console.log(`Server running on port ${PORT}`)); 