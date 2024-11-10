require('dotenv').config();
const express = require('express');
const app = express();
const cors = require('cors');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const validator = require('validator');
const bodyParser = require('body-parser');
const sgMail = require('@sendgrid/mail');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const mongoUri = process.env.MONGODB_URI || 'mongodb+srv://dredderp:6gbfUqmeFELQ83Mu@dredddb.7gkij.mongodb.net/';

// Set up MongoDB connection with mongoose
mongoose.connect(mongoUri)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('Failed to connect to MongoDB:', err));

// Set up SendGrid
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname + "/public"));
app.use('/node_modules', express.static("node_modules"));
app.use(helmet()); 
app.use(cors());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Session Middleware
app.use(session({
  secret: process.env.SESSION_SECRET || 'some-secret-key', 
  resave: false,
  saveUninitialized: true,
  store: MongoStore.create({ mongoUrl: mongoUri }),
  cookie: { secure: process.env.NODE_ENV === 'production' } // Secure cookie for production
}));

// Define Mongoose User and Token models
const tokenSchema = new mongoose.Schema({
  email: { type: String, required: true },
  token: { type: String, required: true },
  createdAt: { type: Date, default: Date.now, expires: 3600 }, // Expires in 1 hour
});
const Token = mongoose.model('Token', tokenSchema);

const userSchema = new mongoose.Schema({
  emaildb: { type: String, required: true },
  password: { type: String, required: true },
  resetKey: String,
  resetExpires: Date,
});
const User = mongoose.model('User', userSchema);

// Authentication Middleware
function isAuthenticated(req, res, next) {
  if (req.session && req.session.userId) {
    next();
  } else {
    res.status(401).json({ success: false, message: 'Unauthorized access.' });
  }
}

// Hash Password Function
function hashPassword(password) {
  const saltRounds = 10;
  return bcrypt.hashSync(password, saltRounds);
}

// Generate Random String for token
function generateRandomString(length) {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  return result;
}

// Sign Up Route
app.post('/signup', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ success: false, message: 'Email and password are required' });
  }

  try {
    const existingUser = await User.findOne({ emaildb: email });
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'Email already registered' });
    }

    if (!isValidPassword(password)) {
      return res.status(400).json({ success: false, message: 'Password does not meet complexity requirements' });
    }

    const hashedPassword = hashPassword(password);
    await User.create({ emaildb: email, password: hashedPassword });

    res.json({ success: true, message: 'Account created successfully' });
  } catch (error) {
    console.error('Error during signup:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// Password Reset Request
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).send('Email is required');

  try {
    let token = await Token.findOne({ email });
    const resetToken = generateRandomString(32);

    if (token) {
      token.token = resetToken;
      await token.save();
    } else {
      await new Token({ email, token: resetToken }).save();
    }

    res.status(200).json({ message: 'Password reset token generated and saved' });
  } catch (error) {
    console.error('Error processing request:', error);
    res.status(500).json({ message: 'Error processing request' });
  }
});

// Send Password Reset Code via Email
async function sendResetCodeEmail(email, resetCode) {
  const msg = {
    to: email,
    from: 'dredderp@gmail.com',
    subject: 'Your Password Reset Code',
    text: `Your password reset code is: ${resetCode}`,
    html: `<p>Your password reset code is:</p><h3>${resetCode}</h3>`,
  };
  try {
    await sgMail.send(msg);
    console.log(`Reset code sent to ${email}`);
  } catch (error) {
    console.error('Error sending email:', error);
    throw new Error('Error sending reset code email');
  }
}

// Send Password Reset Code
app.post('/send-password-reset', async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ emaildb: email });
    if (!user) return res.status(404).json({ message: 'No account with that email exists' });

    const resetCode = generateRandomString(6);
    user.resetKey = resetCode;
    user.resetExpires = new Date(Date.now() + 3600000); // 1-hour expiry
    await user.save();

    await sendResetCodeEmail(email, resetCode);
    res.json({ message: 'Password reset code sent', redirectUrl: '/reset-password.html' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ message: 'Error processing request' });
  }
});

// Reset Password Route
app.post('/reset-password', async (req, res) => {
  const { resetKey, newPassword } = req.body;
  try {
    const user = await User.findOne({ resetKey, resetExpires: { $gt: new Date() } });
    if (!user) {
      return res.status(400).json({ success: false, message: 'Invalid or expired reset key' });
    }

    user.password = hashPassword(newPassword);  // Hash the new password
    user.resetKey = null;
    user.resetExpires = null;
    await user.save();

    res.json({ success: true, message: 'Password reset successfully' });
  } catch (error) {
    console.error('Error resetting password:', error);
    res.status(500).json({ success: false, message: 'Error resetting password' });
  }
});

// Utility function to validate password
function isValidPassword(password) {
  const regex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/;
  return regex.test(password);
}

// Login Rate Limiter
const loginLimiter = rateLimit({
  windowMs: 30 * 60 * 1000, // 30 minutes
  max: 10, // Allow more requests
  message: 'Too many login attempts, please try again later.',
});

app.post('/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;
  try {
    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password are required.' });
    }
    if (!validator.isEmail(email)) {
      return res.status(400).json({ success: false, message: 'Invalid email format.' });
    }

    const user = await User.findOne({ emaildb: email });
    if (!user) {
      return res.status(400).json({ success: false, message: 'Invalid email or password.' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(400).json({ success: false, message: 'Invalid email or password.' });
    }

    req.session.userId = user._id;
    req.session.email = user.emaildb;

    res.json({ success: true, message: 'Login successful' });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// Serve user details (email)
app.get('/user-details', (req, res) => {
  if (req.session && req.session.email) {
    res.json({ email: req.session.email });
  } else {
    res.status(401).json({ message: 'Not authenticated' });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
