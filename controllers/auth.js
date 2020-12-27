const User = require("../models/user");
const { errorHandler } = require("../helpers/dbErrorHandler");
const jwt = require("jsonwebtoken"); //to generate signed token
const expressJwt = require("express-jwt"); //for authorization check

exports.signup = (req, res) => {
  const user = new User(req.body);
  user.save((err, user) => {
    if (err) {
      return res.status(400).json({
        err: errorHandler(err),
      });
    }
    user.salt = undefined;
    user.hashed_password = undefined;
    res.json({
      user,
    });
  });
};

exports.signin = (req, res) => {
  //find user using email
  const { email, password } = req.body;
  User.findOne({ email }, (err, user) => {
    if (err || !user) {
      return res.status(400).json({
        error: "This email has not been registered. Please try again.",
      });
    }

    //if user is found, use authenticate method in User model
    if (!user.authenticate(password)) {
      return res.status(401).json({
        error: "Wrong password. Please try again.",
      });
    }

    //generate signed token with user id and secret
    const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET);
    //persist the token as "login" in cookie with expiry date
    res.cookie("login", token, { expire: new Date() + 99999 });
    //return response with user and token to the frontend
    const { _id, name, email, role } = user;
    return res.json({ token, user: { _id, name, email, role } });
  });
};

exports.signout = (req, res) => {
  res.clearCookie("login");
  res.json({ message: "Signed out!" });
};

//Needs to be logged in
exports.requireSignin = expressJwt({
  secret: process.env.JWT_SECRET,
  userProperty: "auth",
  algorithms: ["HS256"],
});

//Needs to be the currently logged in (authenticated) user
exports.isAuth = (req, res, next) => {
  let user = req.profile && req.auth && req.profile._id == req.auth._id;
  if (!user) {
    res.status(403).json({
      error: "Access Denied",
    });
  }
  next();
};

//Need to be admin
exports.isAdmin = (req, res, next) => {
  if (req.profile.role === 0) {
    res.status(403).json({
      error: "Admin entry only. Access Denied",
    });
  }
  next();
};
