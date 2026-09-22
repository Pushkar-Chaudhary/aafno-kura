const express = require('express');
const app = express();
const postModel = require('./models/post');
const userModel = require('./models/user');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const PORT = process.env.PORT || 3001;

app.set('view engine', 'ejs');
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.get('/', (req, res) => {
  if (req.cookies.token) return res.redirect('/dashboard');
  res.render('index');
});
app.post('/register', async (req, res) => {
  const { email, password, username, name, age } = req.body;
  const user = await userModel.findOne({ email });

  if (user) return res.status(400).send('User is already registered');

  bcrypt.genSalt(10, (err, salt) => {
    if (err) return res.status(500).send('Error creating salt');

    bcrypt.hash(password, salt, async (err, hash) => {
      if (err) return res.status(500).send('Error hashing password');

      await userModel.create({
        username,
        name,
        email,
        age,
        password: hash
      });

      res.redirect('/login');
    });
  });
});
app.get('/login', (req, res) => {
  if (req.cookies.token) return res.redirect('/dashboard');
  res.render('login');
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await userModel.findOne({ email });

  if (!user) return res.status(400).send('Something went wrong');

  bcrypt.compare(password, user.password, (err, result) => {
    if (err || !result) return res.redirect('/login');

    const token = jwt.sign({ email: user.email, userid: user._id }, 'shhhh');
    res.cookie('token', token);
    return res.redirect('/dashboard');
  });
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
    const data = jwt.verify(req.cookies.token, 'shhhh');
    req.user = data;
    return next();
  } catch (err) {
    return res.redirect('/login');
  }
}

app.listen(PORT, () => console.log('Server running on port ' + PORT));