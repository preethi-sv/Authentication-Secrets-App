//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session'); // Step 1
const passport = require('passport'); // Step 1
const passportLocalMongoose = require("passport-local-mongoose"); // Step 1
const GoogleStrategy = require('passport-google-oauth20').Strategy; // Step 10
const findOrCreate = require('mongoose-findorcreate'); // Step 13

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

// Note - On updating code, the server restarts and cookie is deleted in server.
// Step 2 - Place app.use(session()) in this exact location.
app.use(session({ // Step 2
  secret: "Our long little string",
  resave: false,
  saveUninitialized: false,
}));

// Step 3 - After Step 2, Place this.
app.use(passport.initialize()); // Step 3
app.use(passport.session()); // Step 3

mongoose.connect("mongodb://localhost:27017/usersDB", {useNewUrlParser: true, useUnifiedTopology: true});
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  // Step 18 - Each time, when user signs in with user, we save google id
  // to log in the user next time, instead of creating new user again.
  googleId: String // Step 18
});

// Step 4 - Add plugin to Schema.
userSchema.plugin(passportLocalMongoose); // Step 4
// Step 14 - Add mongoose-findorcreate plugin.
userSchema.plugin(findOrCreate); // Step 14

const User = mongoose.model("User", userSchema);

// Step 5 - use local strategy
passport.use(User.createStrategy()); // Step 5

// Step 5 - use static serialize and deserialize of model for passport session support.
// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

// Step 17 - Common serializing and deserializing (session support) by passport
// that works for all strategies (local, google, etc).
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

// Step 11 - Use Google to authenticate
passport.use(new GoogleStrategy({ // Step 11
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    // Step 12 - User.findOrCreate is not a function of mongoose.
    // We need Step 13 & 14 for this to work.
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      // Step 18 - We find googleId in Database, if it exists, login
      // else create a new user and then login the new user.
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res){
  res.render("home");
});

// Step 15 - Get route when user clicks on Sign in with Google.
// passport authenticates with Google and scope is what user info we get back.
app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] }));

// step 16 - After authentication, Google redirects the user to this callback.
app.get("/auth/google/secrets",
  // If auth fails, redirect to login.
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect("/secrets");
});

app.get("/login", function(req, res){
  res.render("login");
});

app.get("/register", function(req, res){
  res.render("register");
});

app.get("/secrets", function(req, res){
  // Step 8 - Check if authenticated and render Secrets page
  if (req.isAuthenticated()) {
    res.render("secrets");
  } else {
    res.redirect("/login");
  }
});

app.get("/logout", function(req, res){
  // Step 9 - Logout and redirect to home page
  req.logout();
  res.redirect("/");
});

app.post("/register", function(req, res) {
  // Step 6 - Register user
  User.register({username: req.body.username}, req.body.password, function(err, user) {
    if (err) {
      console.log(err);
      res.redirect("/register");
    }
    else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      });
    }
  });
});

app.post("/login", function(req, res) {

  const user = new User({
    username: req.body.username,
    password: req.body.password
  });
  // Step 7 - Login User
  req.login(user, function(err) {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      });
    }
  });

});

app.listen(3000, function() {
    console.log("Server started on port 3000.");
});
