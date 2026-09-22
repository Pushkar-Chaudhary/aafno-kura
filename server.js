require('dotenv').config();

const path = require('path');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const postModel = require('./models/post');
const userModel = require('./models/user');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';

// Enable trust proxy for cloud deployment (Vercel, Render, Railway, Cloudflare)
app.set('trust proxy', 1);

// Global cache for MongoDB connection across serverless invocations
let cached = global.mongoose;
if (!cached) {
  cached = global.mongoose = { conn: null, promise: null };
}

const connectDB = async () => {
  if (cached.conn) {
    return cached.conn;
  }

  if (!cached.promise) {
    const mongoUri = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/aafnokura';
    mongoose.set('strictQuery', true);

    cached.promise = mongoose.connect(mongoUri, {
      bufferCommands: false,
      serverSelectionTimeoutMS: 5000
    }).then((mongooseInstance) => {
      console.log('MongoDB connected');
      return mongooseInstance;
    }).catch((err) => {
      cached.promise = null;
      throw err;
    });
  }

  try {
    cached.conn = await cached.promise;
  } catch (err) {
    cached.promise = null;
    throw err;
  }

  return cached.conn;
};

// Database Connection Middleware for Serverless & Cloud deployment
app.use(async (req, res, next) => {
  try {
    await connectDB();
    next();
  } catch (err) {
    console.error('Database connection error:', err);
    res.status(500).send(`
      <div style="font-family: system-ui, -apple-system, sans-serif; padding: 40px; text-align: center; max-width: 600px; margin: 40px auto; border: 1px solid #e2e8f0; border-radius: 12px; background: #ffffff; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);">
        <h2 style="color: #e53e3e; margin-top: 0;">Database Connection Error</h2>
        <p style="color: #4a5568;">Unable to connect to MongoDB. If this is deployed on Vercel, please make sure you have added the <strong>MONGODB_URI</strong> environment variable in your Vercel Project Settings.</p>
        <p style="color: #718096; font-size: 13px; background: #f7fafc; padding: 12px; border-radius: 6px; word-break: break-all; font-family: monospace;">${err.message}</p>
      </div>
    `);
  }
});

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Rate Limiter: Active for security, but explicitly skipped for localhost testing
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    const ip = req.ip || req.socket?.remoteAddress || '';
    const host = req.hostname || req.headers?.host || '';
    return (
      ip === '127.0.0.1' ||
      ip === '::1' ||
      ip === '::ffff:127.0.0.1' ||
      host.includes('localhost') ||
      host.includes('127.0.0.1')
    );
  },
  message: 'Too many requests from this IP, please try again later.'
});
app.use(limiter);

// Authentication Middleware
async function isLoggedIn(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.redirect('/login');

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await userModel.findById(decoded.userid);
    if (!user) {
      res.clearCookie('token');
      return res.redirect('/login');
    }
    req.user = decoded;
    req.currentUser = user;
    return next();
  } catch (err) {
    res.clearCookie('token');
    return res.redirect('/login');
  }
}

// Health Check
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Home Page (Register)
app.get('/', (req, res) => {
  if (req.cookies.token) {
    try {
      jwt.verify(req.cookies.token, JWT_SECRET);
      return res.redirect('/dashboard');
    } catch (e) {
      res.clearCookie('token');
    }
  }
  res.render('index', { error: null, formValues: {} });
});

// Register User
app.post('/register', async (req, res) => {
  const name = String(req.body.name || '').trim();
  const username = String(req.body.username || '').trim().toLowerCase();
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '').trim();
  const rawAge = req.body.age;
  const age = rawAge ? Number(rawAge) : 18;

  const formValues = { name, username, email, age: rawAge || '' };

  if (!name || !username || !email || !password) {
    return res.status(400).render('index', {
      error: 'Please fill in all required fields.',
      formValues
    });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).render('index', {
      error: 'Please enter a valid email address.',
      formValues
    });
  }

  const usernameRegex = /^[a-zA-Z0-9_]{3,30}$/;
  if (!usernameRegex.test(username)) {
    return res.status(400).render('index', {
      error: 'Username must be 3-30 characters (letters, numbers, and underscores only).',
      formValues
    });
  }

  if (password.length < 8) {
    return res.status(400).render('index', {
      error: 'Password must be at least 8 characters long.',
      formValues
    });
  }

  if (isNaN(age) || age < 13) {
    return res.status(400).render('index', {
      error: 'You must be at least 13 years old to register.',
      formValues
    });
  }

  try {
    const existingUser = await userModel.findOne({
      $or: [{ email }, { username }]
    });

    if (existingUser) {
      const isEmailMatch = existingUser.email === email;
      return res.status(400).render('index', {
        error: isEmailMatch
          ? 'An account with that email already exists.'
          : 'That username is already taken.',
        formValues
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await userModel.create({
      name,
      username,
      email,
      password: hashedPassword,
      age
    });

    return res.redirect('/login?registered=1');
  } catch (error) {
    console.error('Register error:', error);
    return res.status(500).render('index', {
      error: 'Something went wrong during account creation. Please try again.',
      formValues
    });
  }
});

// Login Page
app.get('/login', (req, res) => {
  if (req.cookies.token) {
    try {
      jwt.verify(req.cookies.token, JWT_SECRET);
      return res.redirect('/dashboard');
    } catch (e) {
      res.clearCookie('token');
    }
  }
  const registered = req.query.registered === '1';
  res.render('login', { error: null, registered });
});

// Login User
app.post('/login', async (req, res) => {
  const identifier = String(req.body.identifier || req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '').trim();

  if (!identifier || !password) {
    return res.status(400).render('login', {
      error: 'Please enter your username/email and password.',
      registered: false
    });
  }

  try {
    const user = await userModel.findOne({
      $or: [{ email: identifier }, { username: identifier }]
    });

    if (!user) {
      return res.status(400).render('login', {
        error: 'Invalid username/email or password.',
        registered: false
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).render('login', {
        error: 'Invalid username/email or password.',
        registered: false
      });
    }

    const token = jwt.sign(
      { userid: user._id.toString(), email: user.email, username: user.username },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.cookie('token', token, {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    return res.redirect('/dashboard');
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).render('login', {
      error: 'Something went wrong while logging in. Please try again.',
      registered: false
    });
  }
});

// Dashboard
app.get('/dashboard', isLoggedIn, async (req, res) => {
  try {
    const posts = await postModel
      .find({ user: req.currentUser._id })
      .populate('user', 'name username')
      .sort({ date: -1 });

    res.render('dashboard', { user: req.currentUser, posts });
  } catch (err) {
    console.error('Dashboard error:', err);
    res.status(500).send('Internal Server Error');
  }
});

// Feed
app.get('/feed', isLoggedIn, async (req, res) => {
  try {
    const posts = await postModel
      .find({})
      .populate('user', 'name username')
      .populate('comments.user', 'name username')
      .sort({ date: -1 })
      .limit(100);

    res.render('feed', { user: req.currentUser, posts });
  } catch (err) {
    console.error('Feed error:', err);
    res.status(500).send('Internal Server Error');
  }
});

// Profile
app.get('/profile', isLoggedIn, async (req, res) => {
  try {
    const posts = await postModel
      .find({ user: req.currentUser._id })
      .sort({ date: -1 });

    const totalLikes = posts.reduce((acc, p) => acc + (p.likes ? p.likes.length : 0), 0);

    res.render('profile', { user: req.currentUser, posts, totalLikes });
  } catch (err) {
    console.error('Profile error:', err);
    res.status(500).send('Internal Server Error');
  }
});

// Create Post
app.post('/post', isLoggedIn, async (req, res) => {
  const content = String(req.body.content || '').trim();
  if (!content) return res.redirect('/dashboard');

  if (content.length > 2000) {
    return res.redirect('/dashboard');
  }

  try {
    const post = await postModel.create({
      user: req.currentUser._id,
      content
    });

    req.currentUser.posts.push(post._id);
    await req.currentUser.save();

    res.redirect('/dashboard');
  } catch (err) {
    console.error('Create post error:', err);
    res.redirect('/dashboard');
  }
});

// Toggle Like / Unlike
app.post('/post/:id/like', isLoggedIn, async (req, res) => {
  try {
    const post = await postModel.findById(req.params.id);
    if (!post) return res.redirect(req.get('Referer') || '/feed');

    const userIdStr = req.currentUser._id.toString();
    const alreadyLikedIndex = post.likes.findIndex((id) => id.toString() === userIdStr);

    if (alreadyLikedIndex !== -1) {
      post.likes.splice(alreadyLikedIndex, 1);
    } else {
      post.likes.push(req.currentUser._id);
    }

    await post.save();
    res.redirect(req.get('Referer') || '/feed');
  } catch (err) {
    console.error('Like error:', err);
    res.redirect(req.get('Referer') || '/feed');
  }
});

// Add Comment
app.post('/post/:id/comment', isLoggedIn, async (req, res) => {
  const text = String(req.body.comment || '').trim();
  if (!text || text.length > 500) return res.redirect(req.get('Referer') || '/feed');

  try {
    const post = await postModel.findById(req.params.id);
    if (!post) return res.redirect(req.get('Referer') || '/feed');

    post.comments.push({
      user: req.currentUser._id,
      text
    });

    await post.save();
    res.redirect(req.get('Referer') || '/feed');
  } catch (err) {
    console.error('Comment error:', err);
    res.redirect(req.get('Referer') || '/feed');
  }
});

// Edit Post Page
app.get('/post/:id/edit', isLoggedIn, async (req, res) => {
  try {
    const post = await postModel.findById(req.params.id);
    if (!post) return res.redirect('/dashboard');

    if (post.user.toString() !== req.currentUser._id.toString()) {
      return res.status(403).send('Unauthorized to edit this post');
    }

    res.render('edit-post', { user: req.currentUser, post });
  } catch (err) {
    console.error('Edit post GET error:', err);
    res.redirect('/dashboard');
  }
});

// Update Post
app.post('/post/:id/edit', isLoggedIn, async (req, res) => {
  const content = String(req.body.content || '').trim();

  try {
    const post = await postModel.findById(req.params.id);
    if (!post) return res.redirect('/dashboard');

    if (post.user.toString() !== req.currentUser._id.toString()) {
      return res.status(403).send('Unauthorized to edit this post');
    }

    if (content && content.length <= 2000) {
      post.content = content;
      await post.save();
    }

    res.redirect('/dashboard');
  } catch (err) {
    console.error('Edit post POST error:', err);
    res.redirect('/dashboard');
  }
});

// Delete Post
app.post('/post/:id/delete', isLoggedIn, async (req, res) => {
  try {
    const post = await postModel.findById(req.params.id);
    if (!post) return res.redirect('/dashboard');

    if (post.user.toString() !== req.currentUser._id.toString()) {
      return res.status(403).send('Unauthorized to delete this post');
    }

    await postModel.findByIdAndDelete(req.params.id);

    req.currentUser.posts = req.currentUser.posts.filter(
      (id) => id.toString() !== req.params.id
    );
    await req.currentUser.save();

    res.redirect('/dashboard');
  } catch (err) {
    console.error('Delete post error:', err);
    res.redirect('/dashboard');
  }
});

// Logout
app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/login');
});

// 404 Handler
app.use((req, res) => {
  res.status(404).render('404');
});

// Error Handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal Server Error' });
});

const startServer = async () => {
  try {
    await connectDB();
    app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
  } catch (error) {
    console.error('Failed to connect to MongoDB:', error);
    process.exit(1);
  }
};

if (require.main === module) {
  startServer();
}

module.exports = app;