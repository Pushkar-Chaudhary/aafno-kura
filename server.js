require('dotenv').config();

const fs = require('fs');
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');

const postModel = require('./models/post');
const userModel = require('./models/user');
const { sanitizeProfileUpdate } = require('./utils/profile');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET;
const BOOTSTRAP_ADMIN_EMAIL = String(process.env.ADMIN_EMAIL || '').trim().toLowerCase();
const MAX_IMAGE_SIZE = 4 * 1024 * 1024;
if (!JWT_SECRET) throw new Error('JWT_SECRET must be set in the environment.');

// Enable trust proxy for cloud deployment (Vercel, Render, Railway, Cloudflare)
app.set('trust proxy', 1);

// MongoDB connection helper for local and serverless
let dbConnectionPromise;
const connectDB = async () => {
  if (mongoose.connection.readyState === 1) return;
  if (mongoose.connection.readyState === 0 || mongoose.connection.readyState === 3) {
    dbConnectionPromise = null;
  }
  const mongoUri = process.env.MONGODB_URI;
  if (!mongoUri) throw new Error('MONGODB_URI must be set in the environment.');
  mongoose.set('strictQuery', true);
  if (!dbConnectionPromise) {
    dbConnectionPromise = mongoose.connect(mongoUri, {
      serverSelectionTimeoutMS: 5000,
      connectTimeoutMS: 10000,
    }).catch((error) => {
      dbConnectionPromise = null;
      throw error;
    });
  }
  await dbConnectionPromise;
};

// Database Connection Middleware
app.use(async (req, res, next) => {
  try {
    await connectDB();
    next();
  } catch (err) {
    console.error('Database connection error:', err);
    next(err);
  }
});

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_IMAGE_SIZE },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp', 'image/gif'];
    if (allowedTypes.includes(file.mimetype)) {
      return cb(null, true);
    }
    req.fileValidationError = 'Only JPG, PNG, WEBP, and GIF images are allowed.';
    return cb(null, false);
  }
});

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

function imageDataUrl(file) {
  if (!file) return '';
  const signatures = [
    { mime: 'image/jpeg', bytes: [0xff, 0xd8, 0xff] },
    { mime: 'image/png', bytes: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] },
    { mime: 'image/gif', bytes: [0x47, 0x49, 0x46, 0x38] },
    { mime: 'image/webp', bytes: [0x52, 0x49, 0x46, 0x46], webp: [0x57, 0x45, 0x42, 0x50] }
  ];
  const match = signatures.find(({ bytes }) => bytes.every((byte, i) => file.buffer[i] === byte));
  if (!match || (match.webp && !match.webp.every((byte, i) => file.buffer[i + 8] === byte))) {
    throw new Error('The selected file is not a supported image. Choose a JPG, PNG, WEBP, or GIF.');
  }
  return `data:${match.mime};base64,${file.buffer.toString('base64')}`;
}

function removeLegacyUpload(imageUrl) {
  if (!imageUrl || !imageUrl.startsWith('/uploads/')) return;
  const target = path.join(__dirname, 'uploads', path.basename(imageUrl));
  if (fs.existsSync(target)) fs.unlinkSync(target);
}

// Rate Limiter: Active for security, but explicitly skipped for localhost testing
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many requests from this IP, please try again later.'
});
app.use(limiter);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many sign in attempts. Try again in 15 minutes.'
});

// Authentication Middleware
async function isLoggedIn(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.redirect('/login');

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await userModel.findById(decoded.userid).populate('notifications.sender', 'name username');
    if (!user) {
      res.clearCookie('token');
      return res.redirect('/login');
    }
    if ((decoded.tokenVersion || 0) !== (user.tokenVersion || 0)) {
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

function isAdmin(req, res, next) {
  if (!req.currentUser || req.currentUser.role !== 'admin') {
    return res.status(403).send('Administrator access is required.');
  }
  return next();
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
app.post('/register', authLimiter, async (req, res) => {
  const name = String(req.body.name || '').trim();
  const username = String(req.body.username || '').trim().toLowerCase();
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
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

  if (password.length < 8 || password.length > 128) {
    return res.status(400).render('index', {
      error: 'Password must be 8 to 128 characters long.',
      formValues
    });
  }

  if (isNaN(age) || age < 13 || age > 120) {
    return res.status(400).render('index', {
      error: 'Age must be between 13 and 120.',
      formValues
    });
  }

  if (BOOTSTRAP_ADMIN_EMAIL && email === BOOTSTRAP_ADMIN_EMAIL) {
    return res.status(400).render('index', {
      error: 'This email is reserved for the primary administrator account. Sign in with its existing account.',
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
      age,
      role: 'user'
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
app.post('/login', authLimiter, async (req, res) => {
  const identifier = String(req.body.identifier || req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');

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

    if (BOOTSTRAP_ADMIN_EMAIL && user.email === BOOTSTRAP_ADMIN_EMAIL && user.role !== 'admin') {
      user.role = 'admin';
      await user.save();
    }

    const token = jwt.sign(
      { userid: user._id.toString(), email: user.email, username: user.username, tokenVersion: user.tokenVersion || 0 },
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

app.get('/privacy', (req, res) => res.render('privacy'));

app.get('/admin/users', isLoggedIn, isAdmin, async (req, res) => {
  try {
    const users = await userModel.find({}, 'name username email role').sort({ username: 1 });
    res.render('admin-users', {
      user: req.currentUser,
      users,
      bootstrapAdminEmail: BOOTSTRAP_ADMIN_EMAIL,
      error: null,
      message: null
    });
  } catch (error) {
    console.error('Admin user list error:', error);
    res.status(500).send('Could not load user accounts. Please try again.');
  }
});

app.post('/admin/users/:id/role', isLoggedIn, isAdmin, async (req, res) => {
  const role = String(req.body.role || '');
  if (!['user', 'admin'].includes(role)) return res.status(400).send('Choose a valid account role.');
  try {
    const target = await userModel.findById(req.params.id);
    if (!target) return res.status(404).send('Account not found.');
    if (target.email === BOOTSTRAP_ADMIN_EMAIL && role !== 'admin') {
      return res.status(400).send('The primary administrator account cannot be changed to a standard user.');
    }
    if (target.role === 'admin' && role === 'user') {
      target.tokenVersion = (target.tokenVersion || 0) + 1;
    }
    target.role = role;
    await target.save();
    return res.redirect('/admin/users');
  } catch (error) {
    console.error('Admin role update error:', error);
    return res.status(500).send('Could not update this account role. Please try again.');
  }
});

// Dashboard
app.get('/dashboard', isLoggedIn, async (req, res) => {
  try {
    const posts = await postModel
      .find({ user: req.currentUser._id })
      .populate('user', 'name username')
      .sort({ date: -1 });

    res.render('dashboard', { user: req.currentUser, posts, activePage: 'dashboard' });
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

    res.render('feed', { user: req.currentUser, posts, activePage: 'feed' });
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

    res.render('profile', { user: req.currentUser, posts, totalLikes, activePage: 'profile' });
  } catch (err) {
    console.error('Profile error:', err);
    res.status(500).send('Internal Server Error');
  }
});

// Edit Profile
app.get('/profile/edit', isLoggedIn, async (req, res) => {
  try {
    const user = await userModel.findById(req.currentUser._id);
    if (!user) return res.redirect('/login');

    res.render('edit-profile', {
      user,
      error: null,
      values: {
        name: user.name,
        username: user.username,
        email: user.email,
        age: user.age
      }
    });
  } catch (err) {
    console.error('Edit profile GET error:', err);
    res.redirect('/profile');
  }
});

app.post('/profile/edit', isLoggedIn, upload.single('avatar'), async (req, res) => {
  if (req.fileValidationError) {
    return res.status(400).render('edit-profile', {
      user: req.currentUser,
      error: req.fileValidationError,
      values: {
        name: req.body.name,
        username: req.body.username,
        email: req.body.email,
        age: req.body.age || 18
      }
    });
  }

  const rawValues = {
    name: req.body.name,
    username: req.body.username,
    email: req.body.email,
    age: req.body.age || 18
  };

  let sanitized;
  try {
    sanitized = sanitizeProfileUpdate(rawValues);
  } catch (error) {
    return res.status(400).render('edit-profile', {
      user: req.currentUser,
      error: error.message,
      values: rawValues
    });
  }

  try {
    const existingUser = await userModel.findOne({
      $or: [{ email: sanitized.email }, { username: sanitized.username }]
    });

    if (existingUser && existingUser._id.toString() !== req.currentUser._id.toString()) {
      return res.status(400).render('edit-profile', {
        user: req.currentUser,
        error: existingUser.email === sanitized.email
          ? 'That email is already in use.'
          : 'That username is already taken.',
        values: sanitized
      });
    }

    const user = await userModel.findById(req.currentUser._id);
    if (!user) return res.redirect('/login');

    user.name = sanitized.name;
    user.username = sanitized.username;
    user.email = sanitized.email;
    user.age = sanitized.age;

    if (req.body.useDefaultAvatar === '1') {
      removeLegacyUpload(user.avatar);
      user.avatar = '';
    } else if (req.file) {
      user.avatar = imageDataUrl(req.file);
    }

    await user.save();

    req.currentUser = user;
    const token = jwt.sign(
      { userid: user._id.toString(), email: user.email, username: user.username, tokenVersion: user.tokenVersion || 0 },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.cookie('token', token, {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.redirect('/profile');
  } catch (err) {
    console.error('Profile update error:', err);
    res.status(err.message.startsWith('The selected file') ? 400 : 500).render('edit-profile', {
      user: req.currentUser,
      error: err.message.startsWith('The selected file') ? err.message : 'Something went wrong while updating your profile.',
      values: sanitized || rawValues
    });
  }
});

// Create Post
app.post('/post', isLoggedIn, upload.single('image'), async (req, res) => {
  const content = String(req.body.content || '').trim();

  if (req.fileValidationError) {
    return res.status(400).send(req.fileValidationError);
  }

  if (!content && !req.file) {
    return res.redirect('/dashboard');
  }

  if (content.length > 2000) {
    return res.redirect('/dashboard');
  }

  try {
    const post = await postModel.create({
      user: req.currentUser._id,
      content,
      image: imageDataUrl(req.file)
    });

    req.currentUser.posts.push(post._id);
    await req.currentUser.save();

    res.status(err.message.startsWith('The selected file') ? 400 : 500).send(err.message.startsWith('The selected file') ? err.message : 'Could not publish this post. Please try again.');
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

// Add Comment & Trigger Notification
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

    // Trigger notification if commenter is not post author
    if (post.user.toString() !== req.currentUser._id.toString()) {
      const postOwner = await userModel.findById(post.user);
      if (postOwner) {
        postOwner.notifications.unshift({
          sender: req.currentUser._id,
          type: 'comment',
          post: post._id,
          message: `${req.currentUser.name} (@${req.currentUser.username}) commented: "${text.length > 30 ? text.substring(0, 30) + '...' : text}"`,
          read: false,
          date: new Date()
        });
        await postOwner.save();
      }
    }

    res.redirect(req.get('Referer') || '/feed');
  } catch (err) {
    console.error('Comment error:', err);
    res.redirect(req.get('Referer') || '/feed');
  }
});

// Edit Comment
app.post('/post/:postId/comment/:commentId/edit', isLoggedIn, async (req, res) => {
  const text = String(req.body.comment || '').trim();
  if (!text || text.length > 500) return res.redirect(req.get('Referer') || '/feed');

  try {
    const post = await postModel.findById(req.params.postId);
    if (!post) return res.redirect(req.get('Referer') || '/feed');

    const comment = post.comments.id(req.params.commentId);
    if (!comment) return res.redirect(req.get('Referer') || '/feed');

    if (comment.user.toString() !== req.currentUser._id.toString()) {
      return res.status(403).send('Unauthorized to edit this comment');
    }

    comment.text = text;
    await post.save();

    res.redirect(req.get('Referer') || '/feed');
  } catch (err) {
    console.error('Edit comment error:', err);
    res.redirect(req.get('Referer') || '/feed');
  }
});

// Delete Comment
app.post('/post/:postId/comment/:commentId/delete', isLoggedIn, async (req, res) => {
  try {
    const post = await postModel.findById(req.params.postId);
    if (!post) return res.redirect(req.get('Referer') || '/feed');

    const comment = post.comments.id(req.params.commentId);
    if (!comment) return res.redirect(req.get('Referer') || '/feed');

    const isCommentOwner = comment.user.toString() === req.currentUser._id.toString();
    const isPostOwner = post.user.toString() === req.currentUser._id.toString();
    const isAdmin = req.currentUser.role === 'admin';

    if (!isCommentOwner && !isPostOwner && !isAdmin) {
      return res.status(403).send('Unauthorized to delete this comment');
    }

    post.comments.pull(req.params.commentId);
    await post.save();

    res.redirect(req.get('Referer') || '/feed');
  } catch (err) {
    console.error('Delete comment error:', err);
    res.redirect(req.get('Referer') || '/feed');
  }
});

// Notifications Page
app.get('/notifications', isLoggedIn, async (req, res) => {
  try {
    const notifications = req.currentUser.notifications || [];

    // Mark unread as read
    let hasUnread = false;
    notifications.forEach((n) => {
      if (!n.read) {
        n.read = true;
        hasUnread = true;
      }
    });

    if (hasUnread) {
      await req.currentUser.save();
    }

    res.render('notifications', {
      user: req.currentUser,
      notifications,
      activePage: 'notifications'
    });
  } catch (err) {
    console.error('Notifications GET error:', err);
    res.status(500).send('Internal Server Error');
  }
});

// Clear Notifications
app.post('/notifications/clear', isLoggedIn, async (req, res) => {
  try {
    req.currentUser.notifications = [];
    await req.currentUser.save();
    res.redirect('/notifications');
  } catch (err) {
    console.error('Clear notifications error:', err);
    res.redirect('/notifications');
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
app.post('/post/:id/edit', isLoggedIn, upload.single('image'), async (req, res) => {
  const content = String(req.body.content || '').trim();

  if (req.fileValidationError) {
    return res.status(400).send(req.fileValidationError);
  }

  try {
    const post = await postModel.findById(req.params.id);
    if (!post) return res.redirect('/dashboard');

    if (post.user.toString() !== req.currentUser._id.toString()) {
      return res.status(403).send('Unauthorized to edit this post');
    }

    if (content.length > 2000) {
      return res.redirect(`/post/${req.params.id}/edit`);
    }

    if (!content && !post.image && !req.file && req.body.removeImage !== '1') {
      return res.redirect(`/post/${req.params.id}/edit`);
    }

    if (req.body.removeImage === '1') {
      removeLegacyUpload(post.image);
      post.image = '';
    } else if (req.file) {
      post.image = imageDataUrl(req.file);
    }

    post.content = content;
    await post.save();

    res.redirect('/dashboard');
  } catch (err) {
    console.error('Edit post POST error:', err);
    res.status(err.message.startsWith('The selected file') ? 400 : 500)
      .send(err.message.startsWith('The selected file') ? err.message : 'Could not update this post. Please try again.');
  }
});

// Delete Post
app.post('/post/:id/delete', isLoggedIn, async (req, res) => {
  try {
    const post = await postModel.findById(req.params.id);
    if (!post) return res.redirect(req.get('Referer') || '/dashboard');

    const isPostOwner = post.user.toString() === req.currentUser._id.toString();
    const isAdmin = req.currentUser.role === 'admin';

    if (!isPostOwner && !isAdmin) {
      return res.status(403).send('Unauthorized to delete this post');
    }

    if (post.image) {
      removeLegacyUpload(post.image);
    }

    await postModel.findByIdAndDelete(req.params.id);

    // Remove post ID from author's posts list
    const postAuthor = await userModel.findById(post.user);
    if (postAuthor) {
      postAuthor.posts = postAuthor.posts.filter(
        (id) => id.toString() !== req.params.id
      );
      await postAuthor.save();
    }

    res.redirect(req.get('Referer') || '/dashboard');
  } catch (err) {
    console.error('Delete post error:', err);
    res.redirect(req.get('Referer') || '/dashboard');
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
  if (err instanceof multer.MulterError) {
    return res.status(400).send(err.code === 'LIMIT_FILE_SIZE' ? 'Images must be 4 MB or smaller.' : 'The uploaded file could not be processed.');
  }
  res.status(500).send('Something went wrong. Please try again.');
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
