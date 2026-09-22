const mongoose = require('mongoose');

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
        required: true,
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
    posts: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Post' }]
});

module.exports = mongoose.model('User', userSchema);