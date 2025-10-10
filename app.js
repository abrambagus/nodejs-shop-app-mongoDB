const path = require("path");

const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require("express-session");
const MongoDBStore = require("connect-mongodb-session")(session);
const csrf = require("csrf");
const flash = require("connect-flash");

const errorController = require("./controllers/error");
const User = require("./models/user");

const MONGODB_URI =
  "mongodb+srv://abrambagus_db_user:Le8JaOB7qFK7b175@cluster0.d1jikx7.mongodb.net/shop?retryWrites=true&w=majority&appName=Cluster0&tlsAllowInvalidCertificates=true&tlsAllowInvalidHostnames=true";

const app = express();
const store = new MongoDBStore({
  uri: MONGODB_URI,
  collection: "sessions",
});

const tokens = new csrf();

app.set("view engine", "ejs");
app.set("views", "views");

const adminRoutes = require("./routes/admin");
const shopRoutes = require("./routes/shop");
const authRoutes = require("./routes/auth");

app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, "public")));
app.use(
  session({
    secret: "my secret",
    resave: false,
    saveUninitialized: false,
    store: store,
  })
);

// CSRF protection middleware
app.use((req, res, next) => {
  if (
    req.method === "GET" ||
    req.method === "HEAD" ||
    req.method === "OPTIONS"
  ) {
    return next();
  }

  const token = req.body._csrf || req.headers["x-csrf-token"];
  const secret = req.session.csrfSecret;

  if (!secret || !tokens.verify(secret, token)) {
    const error = new Error("Invalid CSRF token");
    error.statusCode = 403;
    return next(error);
  }

  next();
});

app.use(flash());

app.use((req, res, next) => {
  res.locals.isAuthenticated = req.session.isLoggedIn;

  // Generate CSRF token
  if (!req.session.csrfSecret) {
    req.session.csrfSecret = tokens.secretSync();
  }
  res.locals.csrfToken = tokens.create(req.session.csrfSecret);

  next();
});

app.use((req, res, next) => {
  if (!req.session.user) {
    return next();
  }
  User.findById(req.session.user._id)
    .then((user) => {
      if (!user) {
        return next();
      }
      req.user = user;
      next();
    })
    .catch((err) => {
      next(new Error(err));
    });
});

app.use("/admin", adminRoutes);
app.use(shopRoutes);
app.use(authRoutes);

app.get("/500", errorController.get500);

app.use(errorController.get404);

app.use((err, req, res, next) => {
  // res.redirect("/500");
  res.status(500).render("500", {
    pageTitle: "Error!",
    path: "/500",
    isAuthenticated: req.session.isLoggedIn,
  });
});

mongoose
  .connect(MONGODB_URI)
  .then(() => {
    app.listen(3001);
  })
  .catch((err) => {
    console.log(err);
  });
