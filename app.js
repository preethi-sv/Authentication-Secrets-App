//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session'); // Step 1
const passport = require('passport'); // Step 1
const passportLocalMongoose = require("passport-local-mongoose"); // Step 1

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

// Note - On updating code, the server restarts and cookie is deleted in server
// Step 2 - Place app.use(session()) in this exact location
app.use(session({ // Step 2
  secret: "Our long little string",
  resave: false,
  saveUninitialized: false,
}));

// Step 3 - After Step 2 - Place this
app.use(passport.initialize()); // Step 3
app.use(passport.session()); // Step 3

mongoose.connect("mongodb://localhost:27017/usersDB", {useNewUrlParser: true, useUnifiedTopology: true});
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
  email: String,
  password: String
});

//Step 4 - Add plugin to Schema
userSchema.plugin(passportLocalMongoose); // Step 4

const User = mongoose.model("User", userSchema);

// Step 5 - use local strategy
passport.use(User.createStrategy()); // Step 5

// Step 5 - use static serialize and deserialize of model for passport session support
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

app.get("/", function(req, res){
  res.render("home");
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
