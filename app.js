//Necessary packages
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require('mongoose');
const bcrypt = require("bcrypt")
const session = require("express-session")
const passport = require("passport")
const passportLocalMongoose = require("passport-local-mongoose")
const findOrCreate = require('mongoose-findorcreate')
const saltingRound = 10;
// const encrypt = require("mongoose-encryption")
//const md5 = require("md5")
const GoogleStrategy = require('passport-google-oauth20').Strategy;


//Set up default mongoose connection
mongoose.set('strictQuery', true);
mongoose.connect('mongodb://127.0.0.1/userDB', { useNewUrlParser: true });


const app = express() // Setting up express

app.use(express.static("public")) // To be able to use public server
app.set("view engine","ejs"); // Set up ejs
app.use(bodyParser.urlencoded({extended:true})) // Set up body-parser
app.use(session({
    secret:process.env.SECRET_STRING,
    resave: false,
    saveUninitialized:false
}))
app.use(passport.initialize());
app.use(passport.session());


const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    googleId:String,
    secrets:[]
})

// userSchema.plugin(encrypt,{secret:process.env.SECRET_STRING, encryptedFields:["password"]})
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User",userSchema)

passport.use(User.createStrategy())

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      cb(null, { id: user.id, username: user.username });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });
  
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


//Basic routes
app.get("/",function(req,res){
    res.render("home")
})

app.get("/submit",function(req,res){
    if (req.isAuthenticated) {
        res.render("submit")
    } else {
        res.redirect("login")
    }
})

app.get('/auth/google',
passport.authenticate('google', { scope: ["profile"] }));

app.get('/auth/google/secrets', 
passport.authenticate('google', { failureRedirect: '/login' }),
function(req, res) {
// Successful authentication, redirect to secrets.
res.redirect('/secrets');
});

app.get("/login",function(req,res){
    res.render("login")
})

app.get("/register",function(req,res){
    res.render("register")
})

app.get("/secrets",function(req,res){
    User.find(function(err,result){
        if (!err) {
            res.render("secrets",{allUsers:result})
        } else {
            console.log(err);
        }
    })
})
app.get("/logout",function(req,res){
    req.logout(function(err){
        if (err) {
            console.log(err);
        } else {
            res.redirect("/")
        }
    })
})

app.post("/register",function(req,res){
    // bcrypt.hash(req.body.password, saltingRound,function(err,hash){
    //     let username = req.body.username
    //     let password = hash
    //     const newUser = new User({
    //         email:username,
    //         password: password
    //     })
    //     newUser.save(function(err){
    //         if(!err){
    //             res.render("secrets")
    //         }else{
    //             res.send(err)
    //         }
    //     })
    // })
    User.register({username: req.body.username}, req.body.password,function(err,user){
        if (err) {
            console.log(err);
            res.redirect("/register")
        } else {
            passport.authenticate('local')(req, res, function () {
                res.redirect('/secrets');
              });
            }})
        }
    )

app.post("/login",function(req,res){
    const user = new User({
        username: req.body.username,
        password: req.body.password
    })
    req.login(user,function(err){
        if (err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets")
            })
        }
    })
    // User.findOne({email:username},function(err,foundUser){
    //     if (err) {
    //         res.send(err)
    //     } else {
    //         if(foundUser){
    //             bcrypt.compare(password,foundUser.password,function(err,result){
    //                 if(result === true){
    //                     res.render("secrets")
    //                 }
    //             })
    //             }
    //         }
    //     }
    // )
})
app.post("/submit",function(req,res){
    let secret = req.body.secret
    User.findById(req.user.id,function(err,foundUser){
        if (!err) {
            let currentArray = foundUser.secrets
            currentArray.push(secret)
            User.findByIdAndUpdate(req.user.id,{secrets:currentArray}, function(err){
                if (err) {
                    console.log(err);
                }else{
                    res.redirect("secrets")
                }
            })      
        } else {
            console.log(err);
        }
    })
})


app.listen(3000,function(){
    console.log("Server started on port 3000");
})