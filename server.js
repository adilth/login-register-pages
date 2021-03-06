if (process.env.NODE_ENV !== "production") {
  require("dotenv").config();
}
//dependencies
const express = require("express");
const app = express();
const bcrypt = require("bcrypt");
const passport = require("passport");
const flash = require("express-flash");
const session = require("express-session");
const methodOverride = require("method-override");
// const port = process.env.PORT || 8000;
const cors = require("cors");
const initializePassport = require("./passport-config");

initializePassport(
  passport,
  (email) => users.find((user) => user.email === email),
  (id) => users.find((user) => user.id === id)
);
const users = [];

// ========================
// Middlewares
// ========================
app.set("view-engine", "ejs");
app.use(express.static("public"));
app.use(express.urlencoded({ extended: false }));
app.use(flash());
app.use(cors());
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());
app.use(methodOverride("_method"));

// ========================
// Routes
// ========================
app.get("/", ckeckAuthentication, (req, res) => {
  res.render("index.ejs", { name: req.user.name });
});
app.get("/login", ckeckNotAuthentication, (req, res) => {
  res.render("login.ejs");
});
app.post(
  "/login",
  ckeckNotAuthentication,
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login",
    failureFlash: true,
  })
);
app.get("/register", ckeckNotAuthentication, (req, res) => {
  res.render("register.ejs");
});

app.post("/register", ckeckNotAuthentication, async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    users.push({
      id: Date.now().toString(),
      name: req.body.name,
      email: req.body.email,
      password: hashedPassword,
    });
    res.redirect("/login");
  } catch {
    res.redirect("/register");
  }
  console.log(users);
});

app.delete("/logout", function (req, res, next) {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/login");
  });
});

// ========================
// Authenticated
// ========================
function ckeckAuthentication(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/login");
}

function ckeckNotAuthentication(req, res, next) {
  if (req.isAuthenticated()) {
    return res.redirect("/");
  }
  next();
}
// ========================
// Listen
// ========================
app.listen(8000, () => console.log("it's running"));
