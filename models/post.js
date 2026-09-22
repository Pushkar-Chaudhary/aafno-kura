const mongoose = require('mongoose');

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
    comments: [
        {
            user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
            text: String,
            date: { type: Date, default: Date.now }
        }
    ]
});

module.exports = mongoose.model('Post', postSchema);