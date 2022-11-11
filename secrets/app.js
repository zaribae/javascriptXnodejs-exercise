require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const saltRounds = 10;

const app = express();

app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));

mongoose.connect("mongodb://localhost:27017/" + process.env.DBS);

const userSchema = new mongoose.Schema ({
    email: String,
    password: String
});



const User = new mongoose.model("User", userSchema);

app.get('/', (req, res) => {
    res.render("home");
})

app.get('/login', (req, res) => {
    res.render("login");
})

app.get('/register', (req, res) => {
    res.render("register");
})

app.get('/logout', (req, res) => {
    res.render("home");
})

app.post('/register', (req, res) => {
    bcrypt.hash(req.body.password, saltRounds, (err, hash) => {
        const newUser = new User({
            email: req.body.username,
            password: hash
        });
    
        newUser.save((err) => {
            if (!err) {
                res.render("secrets");
            } else {
                res.send(err);
            }
        });
        
    });

})

app.post('/login', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
        User.findOne({email: username}, (err, foundUser) => {
            if (!err) {
                bcrypt.compare(password, foundUser.password, (err, result) => {
                    if (result === true) {
                        res.render("secrets");
                    } else {
                        res.send("Wrong password!!");
                    }
                });
            } else {
                res.send(err);
            }
        })
})

app.listen(8000, () => {
    console.log("Server started on port 8000");
})
