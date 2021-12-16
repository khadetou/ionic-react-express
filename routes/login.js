const express = require("express");
const db = require("../models/index");
const bcrypt = require("bcrypt");

// Passport
const passport = require("passport");
const localStrategy = require("passport-local").Strategy;
const jwt = require("jsonwebtoken");
const JwtStrategy = require("passport-jwt").Strategy;
const { ExtractJwt } = require("passport-jwt");
const saltRounds = 10;

//Database Reference
const { User } = db;

const router = express.Router();

//Passport authentication
passport.use(
  "clientLocal",
  new localStrategy((username, password, done) => {
    User.findOne({
      where: { email: username },
      raw: false,
    })
      .then((user) => {
        if (!user) {
          return done(null, false, { message: "Incorrect username" });
        }
        if (!bycrypt.compareSync(password, user.password)) {
          return done(null, false, { message: "Incorrect password" });
        }
        return done(null, user);
      })
      .catch((err) => {
        null, false, err;
      });
  })
);

passport.use(
  "clientJwt",
  new JwtStrategy(jwtOptions, (jwtPayload, done) => {
    User.findOne({ where: { id: jwtPayload.id }, raw: false })
      .then((user) => {
        if (!user) {
          return done(null, false, { message: "Incorrect username" });
        }
        return done(null, user);
      })
      .catch((err) => (null, false, err));
  })
);

//Register API
router.post("/register", (req, res) => {
  if (req.body.username && req.body.password) {
    User.findOne({ where: { email: req.body.username }, raw: false })
      .then((user) => {
        if (user) {
          res.status(401).json({ message: "User already exists" });
        } else {
          const hash = bcrypt.hashSync(req.body.password, saltRounds);
          User.create({
            email: req.body.username,
            password: hash,
            name: req.body.name,
            phone: req.body.phone,
            type: "client",
            stripeId: req.body.stripeId,
          })
            .then((userNew) => {
              const payload = { id: userNew.id };
              const token = jwt.sign(payload, proccess.env.JWT_SECRET);
              res.json({ token });
            })
            .catch(() => {
              res.status(401).json({ message: "Error Creating User" });
            });
        }
      })
      .catch((err) => {
        res.status(401).json({ message: err });
      });
  } else {
    res.status(401).json({ message: "Missing username or password" });
  }
});

//login API
router.post("/login", (req, res, done) => {
  passport.authenticate("clientLocal", (err, user, info) => {
    if (err) {
      return done(err);
    }
    //Generate a json response reflecting authentication status
    if (!user) {
      return res.status(401).json({ success: false, info });
    }
    req.login(user, (err) => {
      if (err) {
        return done(err);
      }
      const payload = { id: req.user.id };
      const token = jwt.sign(payload, proccess.env.JWT_SECRET);
      return res.json({ token });
    });
  })(req, res, done);
});

//GET USER API
router.get(
  ":/id",
  passport.authenticate(["adminJwt", "driverJwt"], { session: false }),
  (req, res) => {
    const clientId = req.params.id;
    User.findOne({ where: { id: clientId }, raw: false }).then((result) =>
      res.send(result)
    );
  }
);

module.exports = router;
