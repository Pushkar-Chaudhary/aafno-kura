const mongoose = require('mongoose');

const commentSchema = mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    text: { type: String, required: true },
    date: { type: Date, default: Date.now }
});

const postSchema = mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    date: {
        type: Date,
        default: Date.now
    },
    content: String,
    likes: [
        { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
    ],
    comments: [commentSchema]
});

module.exports = mongoose.model('Post', postSchema);