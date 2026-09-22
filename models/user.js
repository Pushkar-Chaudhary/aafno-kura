const mongoose = require('mongoose');
mongoose.connect('mongodb+srv://pushkarchaudhary256_db_user:z6Rv0m626uhtv6ZU@first-backend.pu8xpnw.mongodb.net/project-1');

const userSchema = mongoose.Schema({
    username: String,
    name: String,
    age: Number,
    email: String,
    password: String,
    posts: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Post' }]
});

module.exports = mongoose.model('User', userSchema);