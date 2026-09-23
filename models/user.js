const mongoose = require('mongoose');

const notificationSchema = mongoose.Schema({
    sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    type: { type: String, enum: ['comment', 'like'], default: 'comment' },
    post: { type: mongoose.Schema.Types.ObjectId, ref: 'Post' },
    message: String,
    read: { type: Boolean, default: false },
    date: { type: Date, default: Date.now }
});

const userSchema = mongoose.Schema({
    username: {
        type: String,
        required: true,
        trim: true,
        unique: true,
        lowercase: true
    },
    name: {
        type: String,
        required: true,
        trim: true
    },
    age: {
        type: Number,
        default: 18,
        min: 13
    },
    email: {
        type: String,
        required: true,
        trim: true,
        unique: true,
        lowercase: true
    },
    password: {
        type: String,
        required: true,
        minlength: 8
    },
    posts: {
        type: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Post' }],
        default: []
    },
    notifications: {
        type: [notificationSchema],
        default: []
    }
});

module.exports = mongoose.model('User', userSchema);