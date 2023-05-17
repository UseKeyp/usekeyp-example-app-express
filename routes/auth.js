var express = require("express");
var passport = require("passport");
var OAuth2Strategy = require("passport-oauth2");
const { decode } = require("jsonwebtoken");
var db = require("../db");
const fetch = require("cross-fetch");

// Configure Keyp for use by Passport.js

const KEYP_APP_DOMAIN =
  process.env.KEYP_APP_DOMAIN || "https://app.usekeyp.com";
const KEYP_AUTHORIZATION_URL = `${KEYP_APP_DOMAIN}/oauth/auth`
const KEYP_TOKEN_URL = `${KEYP_APP_DOMAIN}/oauth/token`

// Domain where you serve the app 
const APP_DOMAIN = process.env.APP_DOMAIN || "http://localhost:3000";
const APP_CALLBACK_URL = `${APP_DOMAIN}/redirect/keyp`

passport.use(
  new OAuth2Strategy(
    {
      clientID: process.env.KEYP_CLIENT_ID,
      scope: ["openid", "email"],
      state: true,
      pkce: true,
      authorizationURL: KEYP_AUTHORIZATION_URL,
      tokenURL: KEYP_TOKEN_URL,
      callbackURL: APP_CALLBACK_URL,
    },
    async (accessToken, _refreshToken, params, _profile, cb) => {
      const id_token = decode(params.id_token);

      const userDetails = await fetch(`${KEYP_APP_DOMAIN}/oauth/me`, {
        headers: { Authorization: `Bearer ${accessToken}` },
      }).then((res) => {
        if (res.status != 200)
          cb(new Error("KEYP authorization failed, or secret invalid"));
        return res.json();
      });

      db.get(
        "SELECT * FROM federated_credentials WHERE provider = ? AND user_id = ?",
        [id_token.iss, userDetails.sub],
        function (err, row) {
          if (err) {
            return cb(err);
          }
          if (!row) {
            db.run(
              "INSERT INTO users (id, email, access_token) VALUES (?, ?, ?)",
              [userDetails.sub, userDetails.email, accessToken],
              function (err) {
                if (err) {
                  return cb(err);
                }
                var id = this.lastID;
                db.run(
                  "INSERT INTO federated_credentials (user_id, provider) VALUES (?, ?)",
                  [userDetails.sub, id_token.iss],
                  function (err) {
                    if (err) {
                      return cb(err);
                    }
                    var user = {
                      id: id,
                      name: id_token.sub,
                      accessToken,
                    };
                    return cb(null, user);
                  }
                );
              }
            );
          } else {
            // Update the user's email and access token
            db.run(
              "UPDATE users SET email = ?, access_token = ? WHERE id = ?",
              [userDetails.email, accessToken, userDetails.sub],
              function (err) {
                if (err) {
                  return cb(err);
                }
                db.get(
                  "SELECT * FROM users WHERE id = ?",
                  [row.user_id],
                  function (err, row) {
                    if (err) {
                      return cb(err);
                    }
                    if (!row) {
                      return cb(null, false);
                    }
                    return cb(null, row);
                  }
                );
              }
            );
          }
        }
      );
    }
  )
);

passport.serializeUser(function (user, cb) {
  console.log(user);
  process.nextTick(function () {
    cb(null, {
      id: user.id,
      email: user.email,
      username: user.username,
      access_token: user.access_token,
    });
  });
});

passport.deserializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, user);
  });
});

var router = express.Router();

router.get("/login", function (req, res, next) {
  res.render("login");
});

router.get("/login/keyp", passport.authenticate("oauth2"));

router.get(
  "/redirect/keyp",
  passport.authenticate("oauth2", {
    successReturnToOrRedirect: "/",
    failureRedirect: "/login",
  })
);

router.post("/logout", function (req, res, next) {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

module.exports = router;
