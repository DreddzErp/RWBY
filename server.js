<<<<<<< HEAD
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const validator = require('validator');
const bodyParser = require('body-parser');
const sgMail = require('@sendgrid/mail');
const mongoose = require('mongoose');
const { MongoClient } = require('mongodb'); // Import MongoClient here
const bcrypt = require('bcrypt');

const PORT = process.env.PORT || 3000;

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname + '/public'));
app.use(helmet()); 
app.use(cors());

// Hash Password Function
function hashPassword(password) {
  const saltRounds = 10;
  return bcrypt.hashSync(password, saltRounds);
}

// Configure SendGrid API Key
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// MongoDB setup
const mongoUri = process.env.MONGODB_URI || 'mongodb+srv://dredderp:6gbfUqmeFELQ83Mu@dredddb.7gkij.mongodb.net/';
const client = new MongoClient(mongoUri, { useUnifiedTopology: true }); 
let usersCollection;

async function connectToDatabase() {
  try {
    await client.connect();
    console.log('MongoDB connected');
    const database = client.db('test');
    usersCollection = database.collection('users'); 
  } catch {
    console.error('Failed to connect to MongoDB', err);
    process.exit(1);
  }
}

connectToDatabase();

// Mongoose Connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('Mongoose connected'))
  .catch((error) => console.error('Mongoose connection error:', error));

// Define Token Schema and Model
const tokenSchema = new mongoose.Schema({
  email: { type: String, required: true },
  token: { type: String, required: true },
  createdAt: { type: Date, default: Date.now, expires: 3600 }, // Expires in 1 hour
});
const Token = mongoose.model('Token', tokenSchema);

// Define User Schema and Model
const userSchema = new mongoose.Schema({
  emaildb: { type: String, required: true },
  password: { type: String, required: true },
  resetKey: String,
  resetExpires: Date,
});
const User = mongoose.model('User', userSchema);

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public'));

// Generate Random String
function generateRandomString(length) {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  return result;
}

// Forgot Password Endpoint
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

// Send Reset Code Email
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

// Reset Password
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

    // Send success response
    res.json({ success: true, message: 'Password reset successfully' });
  } catch (error) {
    console.error('Error resetting password:', error);
    res.status(500).json({ success: false, message: 'Error resetting password' });
  }
});


// Sign Up
app.post('/signup', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ success: false, message: 'Email and password are required' });
  }

  try {
    const existingUser = await usersCollection.findOne({ emaildb: email });
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'Email already registered' });
    }

    if (!isValidPassword(password)) {
      return res.status(400).json({ success: false, message: 'Password does not meet complexity requirements' });
    }

    const hashedPassword = hashPassword(password);
    await usersCollection.insertOne({ emaildb: email, password: hashedPassword, createdAt: new Date() });

    // Success response with the success field set to true
    res.json({ success: true, message: 'Account created successfully' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});


function isValidPassword(password) {
  const regex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/;
  return regex.test(password);
}

//login rate limiter
const loginLimiter = rateLimit({
  windowMs: 30 * 60 * 1000, // 30 minutes
  max: 5, // Limit each IP to 5 requests per windowMs
  message: 'Too many login attempts, please try again after 30 minutes.',
  handler: function (req, res, next, options) {
  res.status(options.statusCode).json({ success: false, message: options.message });
  }
  });

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,  
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: mongoUri }),
    cookie: {
      secure: false, // Set to true if using HTTPS
      httpOnly: true,
      sameSite: 'lax',
      maxAge: 30 * 60 * 1000 // 30 minutes session expiry
    }
  }));

// Middleware for authentication
function isAuthenticated(req, res, next) {
  if (req.session && req.session.userId) {
  next();
  } else {
  res.status(401).json({ success: false, message: 'Unauthorized access.' });
  }
}

// Define your routes after the session middleware
app.post('/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;
  try {
    // Input validation
    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password are required.' });
    }
    if (!validator.isEmail(email)) {
      return res.status(400).json({ success: false, message: 'Invalid email format.' });
    }

    // Fetch user
    const user = await usersCollection.findOne({ emaildb: email });
    if (!user) {
      return res.status(400).json({ success: false, message: 'Invalid email or password.' });
    }

    // Account lockout check
    if (user.accountLockedUntil && user.accountLockedUntil > new Date()) {
      const remainingTime = Math.ceil((user.accountLockedUntil - new Date()) / 60000);
      return res.status(403).json({ success: false, message: `Account is locked. Try again in ${remainingTime} minutes.` });
    }

    // Password verification
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      // Handle failed attempts
      let invalidAttempts = (user.invalidLoginAttempts || 0) + 1;
      let updateFields = { invalidLoginAttempts: invalidAttempts };
      if (invalidAttempts >= 3) {
        // Lock account
        updateFields.accountLockedUntil = new Date(Date.now() + 30 * 60 * 1000);
        updateFields.invalidLoginAttempts = 0;
        await usersCollection.updateOne({ _id: user._id }, { $set: updateFields });
        return res.status(403).json({ success: false, message: 'Account is locked due to multiple failed login attempts. Please try again after 30 minutes.' });
      } else {
        await usersCollection.updateOne({ _id: user._id }, { $set: updateFields });
        return res.status(400).json({ success: false, message: 'Invalid email or password.' });
      }
    }

    // Successful login
    await usersCollection.updateOne(
      { _id: user._id },
      { $set: { invalidLoginAttempts: 0, accountLockedUntil: null, lastLoginTime: new Date() } }
    );
    req.session.userId = user._id;
    req.session.email = user.emaildb;
    req.session.role = user.role;
    req.session.studentIDNumber = user.studentIDNumber;
    
    // Save session
    await new Promise((resolve, reject) => {
      req.session.save((err) => {
        if (err) return reject(err);
        resolve();
      });
    });

    res.json({ success: true, role: user.role, message: 'Login successful!' });
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ success: false, message: 'Error during login.' });
  }
});


//dashboard route
app.get('/dashboard', isAuthenticated, (req, res) => {
  res.sendFile(__dirname + '/public/dashboard.html');
  });

// fetch user details route
app.get('/user-details', isAuthenticated, async (req, res) => {
  try {
  const email = req.session.email;
  if (!email) {
  return res.status(401).json({ success: false, message: 'Unauthorized access.' });
  }
  // Fetch user details from the database
  const user = await usersCollection.findOne(
  { emaildb: email },
  { projection: { emaildb: 1 } }
  );
  if (!user) {
  return res.status(404).json({ success: false, message: 'User not found.' });
  }
  // Return only necessary details
  res.json({
  success: true,
  user: {
  email: user.emaildb
  }
  });
  } catch (error) {
  console.error('Error fetching user details:', error);
  res.status(500).json({ success: false, message: 'Error fetching user details.' });
  }
  });


// Logout Route
app.post('/logout', async (req, res) => {
  if (!req.session.userId) {
  return res.status(400).json({ success: false, message: 'No user is logged in.' });
  }
  try {
  req.session.destroy(err => {
  if (err) {
  console.error('Error destroying session:', err);
  return res.status(500).json({ success: false, message: 'Logout failed.' });
  }
  res.clearCookie('connect.sid');
  
  res.json({ success: true, message: 'Logged out successfully.' });
  });
  } catch (error) {
  console.error('Error during logout:', error);
  res.status(500).json({ success: false, message: 'Logout failed.' });
  }
  });


// Start Server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
=======
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const validator = require('validator');
const bodyParser = require('body-parser');
const sgMail = require('@sendgrid/mail');
const mongoose = require('mongoose');
const { MongoClient } = require('mongodb'); // Import MongoClient here
const bcrypt = require('bcrypt');

const PORT = process.env.PORT || 3000;

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname + '/public'));
app.use(helmet()); 
app.use(cors());

// Hash Password Function
function hashPassword(password) {
  const saltRounds = 10;
  return bcrypt.hashSync(password, saltRounds);
}

// Configure SendGrid API Key
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// MongoDB setup
const mongoUri = process.env.MONGODB_URI || 'mongodb+srv://dredderp:6gbfUqmeFELQ83Mu@dredddb.7gkij.mongodb.net/';
const client = new MongoClient(mongoUri, { useUnifiedTopology: true }); 
let usersCollection;

async function connectToDatabase() {
  try {
    await client.connect();
    console.log('MongoDB connected');
    const database = client.db('test');
    usersCollection = database.collection('users'); 
  } catch {
    console.error('Failed to connect to MongoDB', err);
    process.exit(1);
  }
}

connectToDatabase();

// Mongoose Connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('Mongoose connected'))
  .catch((error) => console.error('Mongoose connection error:', error));

// Define Token Schema and Model
const tokenSchema = new mongoose.Schema({
  email: { type: String, required: true },
  token: { type: String, required: true },
  createdAt: { type: Date, default: Date.now, expires: 3600 }, // Expires in 1 hour
});
const Token = mongoose.model('Token', tokenSchema);

// Define User Schema and Model
const userSchema = new mongoose.Schema({
  emaildb: { type: String, required: true },
  password: { type: String, required: true },
  resetKey: String,
  resetExpires: Date,
});
const User = mongoose.model('User', userSchema);

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public'));

// Generate Random String
function generateRandomString(length) {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  return result;
}

// Forgot Password Endpoint
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

// Send Reset Code Email
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

// Reset Password
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

    // Send success response
    res.json({ success: true, message: 'Password reset successfully' });
  } catch (error) {
    console.error('Error resetting password:', error);
    res.status(500).json({ success: false, message: 'Error resetting password' });
  }
});


// Sign Up
app.post('/signup', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ success: false, message: 'Email and password are required' });
  }

  try {
    const existingUser = await usersCollection.findOne({ emaildb: email });
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'Email already registered' });
    }

    if (!isValidPassword(password)) {
      return res.status(400).json({ success: false, message: 'Password does not meet complexity requirements' });
    }

    const hashedPassword = hashPassword(password);
    await usersCollection.insertOne({ emaildb: email, password: hashedPassword, createdAt: new Date() });

    // Success response with the success field set to true
    res.json({ success: true, message: 'Account created successfully' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});


function isValidPassword(password) {
  const regex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/;
  return regex.test(password);
}

//login rate limiter
const loginLimiter = rateLimit({
  windowMs: 30 * 60 * 1000, // 30 minutes
  max: 5, // Limit each IP to 5 requests per windowMs
  message: 'Too many login attempts, please try again after 30 minutes.',
  handler: function (req, res, next, options) {
  res.status(options.statusCode).json({ success: false, message: options.message });
  }
  });

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,  
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: mongoUri }),
    cookie: {
      secure: false, // Set to true if using HTTPS
      httpOnly: true,
      sameSite: 'lax',
      maxAge: 30 * 60 * 1000 // 30 minutes session expiry
    }
  }));

// Middleware for authentication
function isAuthenticated(req, res, next) {
  if (req.session && req.session.userId) {
  next();
  } else {
  res.status(401).json({ success: false, message: 'Unauthorized access.' });
  }
}

// Define your routes after the session middleware
app.post('/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;
  try {
    // Input validation
    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password are required.' });
    }
    if (!validator.isEmail(email)) {
      return res.status(400).json({ success: false, message: 'Invalid email format.' });
    }

    // Fetch user
    const user = await usersCollection.findOne({ emaildb: email });
    if (!user) {
      return res.status(400).json({ success: false, message: 'Invalid email or password.' });
    }

    // Account lockout check
    if (user.accountLockedUntil && user.accountLockedUntil > new Date()) {
      const remainingTime = Math.ceil((user.accountLockedUntil - new Date()) / 60000);
      return res.status(403).json({ success: false, message: `Account is locked. Try again in ${remainingTime} minutes.` });
    }

    // Password verification
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      // Handle failed attempts
      let invalidAttempts = (user.invalidLoginAttempts || 0) + 1;
      let updateFields = { invalidLoginAttempts: invalidAttempts };
      if (invalidAttempts >= 3) {
        // Lock account
        updateFields.accountLockedUntil = new Date(Date.now() + 30 * 60 * 1000);
        updateFields.invalidLoginAttempts = 0;
        await usersCollection.updateOne({ _id: user._id }, { $set: updateFields });
        return res.status(403).json({ success: false, message: 'Account is locked due to multiple failed login attempts. Please try again after 30 minutes.' });
      } else {
        await usersCollection.updateOne({ _id: user._id }, { $set: updateFields });
        return res.status(400).json({ success: false, message: 'Invalid email or password.' });
      }
    }

    // Successful login
    await usersCollection.updateOne(
      { _id: user._id },
      { $set: { invalidLoginAttempts: 0, accountLockedUntil: null, lastLoginTime: new Date() } }
    );
    req.session.userId = user._id;
    req.session.email = user.emaildb;
    req.session.role = user.role;
    req.session.studentIDNumber = user.studentIDNumber;
    
    // Save session
    await new Promise((resolve, reject) => {
      req.session.save((err) => {
        if (err) return reject(err);
        resolve();
      });
    });

    res.json({ success: true, role: user.role, message: 'Login successful!' });
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ success: false, message: 'Error during login.' });
  }
});


//dashboard route
app.get('/dashboard', isAuthenticated, (req, res) => {
  res.sendFile(__dirname + '/public/dashboard.html');
  });

// fetch user details route
app.get('/user-details', isAuthenticated, async (req, res) => {
  try {
  const email = req.session.email;
  if (!email) {
  return res.status(401).json({ success: false, message: 'Unauthorized access.' });
  }
  // Fetch user details from the database
  const user = await usersCollection.findOne(
  { emaildb: email },
  { projection: { emaildb: 1 } }
  );
  if (!user) {
  return res.status(404).json({ success: false, message: 'User not found.' });
  }
  // Return only necessary details
  res.json({
  success: true,
  user: {
  email: user.emaildb
  }
  });
  } catch (error) {
  console.error('Error fetching user details:', error);
  res.status(500).json({ success: false, message: 'Error fetching user details.' });
  }
  });


// Logout Route
app.post('/logout', async (req, res) => {
  if (!req.session.userId) {
  return res.status(400).json({ success: false, message: 'No user is logged in.' });
  }
  try {
  req.session.destroy(err => {
  if (err) {
  console.error('Error destroying session:', err);
  return res.status(500).json({ success: false, message: 'Logout failed.' });
  }
  res.clearCookie('connect.sid');
  
  res.json({ success: true, message: 'Logged out successfully.' });
  });
  } catch (error) {
  console.error('Error during logout:', error);
  res.status(500).json({ success: false, message: 'Logout failed.' });
  }
  });


// Start Server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
>>>>>>> aee91a795f565604a63afdd6f787795d54561ee1
