# Aafnokura - Social Web Application

A minimal, fast, and user-friendly social application built with Node.js, Express, EJS, and MongoDB.

## Features
- **Account Registration & Login**: Flexible login with **Email OR Username**, password hashing via `bcrypt`, and JWT authentication.
- **Dashboard**: Personal post management, post composer, and like/unlike tracking.
- **Community Feed**: Public feed displaying user updates, like toggles, and comment discussions.
- **Profile Page**: User stats (total posts, total likes received) and post history.
- **Deployment & Production Security**: Rate limiting (with localhost testing bypass), proxy trust enabled, Helmet security headers, custom 404 page, and dynamic PORT binding.

---

## Local Development

1. Clone or download the repository.
2. Install dependencies:
   ```bash
   npm install
   ```
3. Copy `.env.example` to `.env` and configure your environment variables:
   ```env
   PORT=3001
   MONGODB_URI=mongodb+srv://<username>:<password>@<cluster>.mongodb.net/project-1
   JWT_SECRET=your_jwt_secret_here
   NODE_ENV=development
   ```
4. Start the server:
   ```bash
   npm run dev
   # or
   npm start
   ```
5. Open your browser and navigate to `http://localhost:3001`.

---

## Production Deployment Guide

This app is production-ready for deployment on hosting services such as **Render**, **Railway**, **Fly.io**, or **Vercel**.

### Deployment Steps (e.g. Render / Railway):
1. Push your repository to GitHub.
2. Create a new **Web Service** on Render / Railway and connect your repository.
3. Set the **Build Command**:
   ```bash
   npm install
   ```
4. Set the **Start Command**:
   ```bash
   npm start
   ```
5. Add the following **Environment Variables**:
   - `NODE_ENV`: `production`
   - `MONGODB_URI`: Your MongoDB Atlas connection URI
   - `JWT_SECRET`: A long random secret string
