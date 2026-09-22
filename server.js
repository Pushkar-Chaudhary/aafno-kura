const express = require('express');
const app = express();
const postModel=require("./models/post")
const userModel = require("./models/user")
const cookieParser=require('cookie-parser');
app.set("view engine","ejs");
app.use(express.json());
const bcrypt= require('bcrypt');
const jwt=require('jsonwebtoken')
app.use(express.urlencoded({extended:true}));
app.use(cookieParser());
app.get("/",(req,res)=>{
    res.render("index")
})
app.post("/register", async (req, res) => {
    const { email, password, username, name, age } = req.body;
    const user = await userModel.findOne({ email });

    if (user) return res.status(400).send("User is already registered");

    bcrypt.genSalt(10, (err, salt) => {
        if (err) return res.status(500).send("Error creating salt");

        bcrypt.hash(password, salt, async (err, hash) => {
            if (err) return res.status(500).send("Error hashing password");

            const createdUser = await userModel.create({
                username,
                name,
                email,
                age,
                password: hash
            });

            const token = jwt.sign(
                { email: createdUser.email, userid: createdUser._id },
                "shhhh"
            );

            res.cookie('token', token);
            res.status(201).send("registered");
        });
    });
});
app.get("/login",(req,res)=>{
    res.render("login");
})
app.get("/profile", isLoggedIn, async (req, res) => {
    const user = await userModel.findOne({ email: req.user.email }).populate("posts");
    if (!user) return res.redirect("/login");
    res.render("profile", { user });
});
app.post("/post", isLoggedIn, async (req, res) => {
    const user = await userModel.findOne({ email: req.user.email });
    const { content } = req.body;

    const post = await postModel.create({
        user: user._id,
        content
    });

    user.posts.push(post._id);
    await user.save();

    res.redirect("/profile");
});
app.post("/post/:id/like", isLoggedIn, async (req, res) => {
    const post = await postModel.findById(req.params.id);
    if (!post) return res.redirect("/profile");

    const alreadyLiked = post.likes.some((id) => id.toString() === req.user.userid);
    if (!alreadyLiked) {
        post.likes.push(req.user.userid);
        await post.save();
    }

    res.redirect("/profile");
});
app.get("/post/:id/edit", isLoggedIn, async (req, res) => {
    const post = await postModel.findById(req.params.id);
    if (!post) return res.redirect("/profile");
    if (post.user.toString() !== req.user.userid) return res.status(403).send("Not allowed");

    res.render("edit-post", { post });
});
app.post("/post/:id/edit", isLoggedIn, async (req, res) => {
    const post = await postModel.findById(req.params.id);
    if (!post) return res.redirect("/profile");
    if (post.user.toString() !== req.user.userid) return res.status(403).send("Not allowed");

    post.content = req.body.content;
    await post.save();
    res.redirect("/profile");
});
app.post("/post/:id/delete", isLoggedIn, async (req, res) => {
    const post = await postModel.findById(req.params.id);
    if (!post) return res.redirect("/profile");
    if (post.user.toString() !== req.user.userid) return res.status(403).send("Not allowed");

    await postModel.findByIdAndDelete(req.params.id);

    const user = await userModel.findOne({ email: req.user.email });
    user.posts = user.posts.filter((id) => id.toString() !== req.params.id);
    await user.save();

    res.redirect("/profile");
});
app.post("/login", async (req, res) => {
   let{email,password}=req.body;
    const user = await userModel.findOne({ email });
    if (!user) return res.status(500).send("Something went wrong");
    bcrypt.compare(password,user.password,(err,result)=>{
        if(result){
            const token = jwt.sign({ email: user.email, userid: user._id }, "shhhh");
            res.cookie('token', token);
            return res.status(200).send("You can login");
        }
        return res.redirect("/login");
    })
});
app.get("/logout",(req,res)=>{
    res.cookie("token","");
        res.redirect("/login");
})
function isLoggedIn(req, res, next) {
    if (!req.cookies.token) {
        res.redirect("/login");
    }

    try {
        const data = jwt.verify(req.cookies.token, "shhhh");
        req.user = data;
        return next();
    } catch (err) {
        return res.send("Invalid token");
    }
}

app.listen(3001, () => console.log("Server running on port 3001"));