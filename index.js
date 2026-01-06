require('dotenv').config();
const express = require('express');
const cors = require('cors');
const connectDB = require('./config/db');
const authRoutes = require('./routes/auth');

const app = express();
connectDB();

/**
 * Allowed frontend origins
 */
const allowedOrigins = [
  'https://eaiser.ai',
  'https://www.eaiser.ai',
];

app.use(
  cors({
    origin: function (origin, callback) {
      // allow server-to-server & tools like Postman
      if (!origin) return callback(null, true);

      if (allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error('CORS not allowed for this origin'));
      }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
  })
);

// Handle preflight requests behavior manually if needed, or let regex handle it.
// The error 'Missing parameter name at index 1: *' suggests '*' string path is treated as a param.
// Using regex /(.*)/ matches everything safely.
app.options(/(.*)/, cors());

app.use(express.json());

/**
 * Routes
 */
app.use('/api/auth', authRoutes);

app.get('/', (req, res) => {
  res.json({ ok: true, msg: 'Eaiser AI backend running' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
