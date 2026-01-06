require('dotenv').config();
const express = require('express');
const cors = require('cors');
const connectDB = require('./config/db');
const authRoutes = require('./routes/auth');

const app = express();
connectDB();

// app.use(cors());
// app.use(express.json());

app.use(cors({
  origin: ['https://www.eaiser.ai'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

app.options(/(.*)/, cors()); // 🔴 IMPORTANT for preflight

app.use(express.json());


app.use('/api/auth', authRoutes);

app.get('/', (req, res) => res.json({ ok: true, msg: 'Eaiser AI backend' }));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
