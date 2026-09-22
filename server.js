require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');
const app = express();
const postModel = require('./models/post');
const userModel = require('./models/user');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';

if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1);
}

const connectDB = async () => {
  const mongoUri = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/aafnokura';
  mongoose.set('strictQuery', true);
  await mongoose.connect(mongoUri);
  console.log('MongoDB connected');
};

app.set('view engine', 'ejs');
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many requests from this IP, please try again later.'
}));

app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.get('/', (req, res) => {
  if (req.cookies.token) return res.redirect('/dashboard');
  res.render('index', { error: null, formValues: {} });
});

app.post('/register', async (req, res) => {
  try {
    const name = String(req.body.name || '').trim();
    const username = String(req.body.username || '').trim();
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '').trim();
    const age = Number(req.body.age);

    if (!name || !username || !email || !password || !Number.isInteger(age) || age < 13) {
      return res.status(400).render('index', {
        error: 'Please enter a valid name, username, age, email, and a password with at least 8 characters.',
        formValues: { name, username, age: Number.isInteger(age) ? age : '', email }
      });
    }

    if (password.length < 8) {
      return res.status(400).render('index', {
        error: 'Password must be at least 8 characters long.',
        formValues: { name, username, age, email }
      });
    }

    const existingUser = await userModel.findOne({
      $or: [{ email }, { username: username.toLowerCase() }]
    });

    if (existingUser) {
      return res.status(400).render('index', {
        error: 'An account with that username or email already exists.',
        formValues: { name, username, age, email }
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await userModel.create({
      username: username.toLowerCase(),
      name,
      email,
      age,
      password: hashedPassword
    });

    return res.redirect('/login');
  } catch (error) {
    console.error('Register error:', error);

    if (error && error.code === 11000) {
      return res.status(400).render('index', {
        error: 'That username or email is already in use.',
        formValues: {
          name: String(req.body.name || '').trim(),
          username: String(req.body.username || '').trim(),
          age: Number(req.body.age),
          email: String(req.body.email || '').trim().toLowerCase()
        }
      });
    }

    return res.status(500).render('index', {
      error: 'Something went wrong while creating your account. Please try again.',
      formValues: {
        name: String(req.body.name || '').trim(),
        username: String(req.body.username || '').trim(),
        age: Number(req.body.age),
        email: String(req.body.email || '').trim().toLowerCase()
      }
    });
  }
});

app.get('/login', (req, res) => {
  if (req.cookies.token) return res.redirect('/dashboard');
  res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '').trim();
    const user = await userModel.findOne({ email });

    if (!user) {
      return res.status(400).render('login', { error: 'Invalid email or password.' });
    }

    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    if (!isPasswordCorrect) {
      return res.status(400).render('login', { error: 'Invalid email or password.' });
    }

      const token = jwt.sign({ email: user.email, userid: user._id.toString() }, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });
    return res.redirect('/dashboard');
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).render('login', { error: 'Something went wrong while logging in. Please try again.' });
  }
});

app.get('/dashboard', isLoggedIn, async (req, res) => {
  const user = await userModel.findOne({ email: req.user.email }).populate('posts');
  const posts = await postModel.find({ user: user._id }).populate('user', 'name username').sort({ date: -1 });

  res.render('dashboard', { user, posts });
});

app.get('/feed', isLoggedIn, async (req, res) => {
  const user = await userModel.findOne({ email: req.user.email });
  const posts = await postModel.find({}).populate('user', 'name username').populate('comments.user', 'name username').sort({ date: -1 });

  res.render('feed', { user, posts });
});

app.get('/profile', isLoggedIn, async (req, res) => {
  const user = await userModel.findOne({ email: req.user.email }).populate('posts');
  if (!user) return res.redirect('/login');

  res.render('profile', { user });
});

app.post('/post', isLoggedIn, async (req, res) => {
  const user = await userModel.findOne({ email: req.user.email });
  const { content } = req.body;

  if (!content || !content.trim()) return res.redirect('/dashboard');

  const post = await postModel.create({
    user: user._id,
    content: content.trim()
  });

  user.posts.push(post._id);
  await user.save();

  res.redirect('/dashboard');
});

app.post('/post/:id/like', isLoggedIn, async (req, res) => {
  const post = await postModel.findById(req.params.id);
  if (!post) return res.redirect('/feed');

  const alreadyLiked = post.likes.some((id) => id.toString() === req.user.userid);
  if (!alreadyLiked) {
    post.likes.push(req.user.userid);
    await post.save();
  }

  res.redirect(req.get('Referer') || '/feed');
});

app.post('/post/:id/comment', isLoggedIn, async (req, res) => {
  const post = await postModel.findById(req.params.id);
  const { comment } = req.body;

  if (!post || !comment || !comment.trim()) return res.redirect(req.get('Referer') || '/feed');

  post.comments.push({
    user: req.user.userid,
    text: comment.trim()
  });

  await post.save();
  res.redirect(req.get('Referer') || '/feed');
});

app.get('/post/:id/edit', isLoggedIn, async (req, res) => {
  const post = await postModel.findById(req.params.id);
  if (!post) return res.redirect('/dashboard');
  if (post.user.toString() !== req.user.userid) return res.status(403).send('Not allowed');

  res.render('edit-post', { post });
});

app.post('/post/:id/edit', isLoggedIn, async (req, res) => {
  const post = await postModel.findById(req.params.id);
  if (!post) return res.redirect('/dashboard');
  if (post.user.toString() !== req.user.userid) return res.status(403).send('Not allowed');

  post.content = req.body.content.trim();
  await post.save();
  res.redirect('/dashboard');
});

app.post('/post/:id/delete', isLoggedIn, async (req, res) => {
  const post = await postModel.findById(req.params.id);
  if (!post) return res.redirect('/dashboard');
  if (post.user.toString() !== req.user.userid) return res.status(403).send('Not allowed');

  await postModel.findByIdAndDelete(req.params.id);

  const user = await userModel.findOne({ email: req.user.email });
  user.posts = user.posts.filter((id) => id.toString() !== req.params.id);
  await user.save();

  res.redirect('/dashboard');
});

app.get('/logout', (req, res) => {
  res.cookie('token', '', { maxAge: 0 });
  res.redirect('/login');
});

function isLoggedIn(req, res, next) {
  if (!req.cookies.token) return res.redirect('/login');

  try {
    const data = jwt.verify(req.cookies.token, JWT_SECRET);
    req.user = data;
    return next();
  } catch (err) {
    return res.redirect('/login');
  }
}

const startServer = async () => {
  try {
    await connectDB();
    app.listen(PORT, () => console.log('Server running on port ' + PORT));
  } catch (error) {
    console.error('Failed to connect to MongoDB:', error);
    process.exit(1);
  }
};

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal Server Error' });
});

if (require.main === module) {
  startServer();
}

module.exports = { app, connectDB };