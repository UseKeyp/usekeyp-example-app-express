var express = require("express");
var passport = require("passport");
var OAuth2Strategy = require("passport-oauth2");
const { decode } = require("jsonwebtoken");
var db = require("../db");
const fetch = require("cross-fetch");

// Configure Keyp for use by Passport.js
//
// OAuth 2.0-based strategies require a `verify` function which receives the
// credential (`accessToken`) for accessing the Facebook API on the user's
// behalf, along with the user's profile.  The function must invoke `cb`
// with a user object, which will be set at `req.user` in route handlers after
// authentication.

const KEYP_APP_DOMAIN =
  process.env.KEYP_APP_DOMAIN || "https://app.usekeyp.com";

const APP_DOMAIN = process.env.APP_DOMAIN || "http://localhost:3000";

passport.use(
  new OAuth2Strategy(
    {
      authorizationURL: `${KEYP_APP_DOMAIN}/oauth/auth`,
      tokenURL: `${KEYP_APP_DOMAIN}/oauth/token`,
      clientID: process.env.KEYP_CLIENT_ID,
      callbackURL: `${APP_DOMAIN}/redirect/keyp`,
      scope: ["openid", "email"],
      state: true,
      pkce: true,
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

// Configure Passport authenticated session persistence.
//
// In order to restore authentication state across HTTP requests, Passport needs
// to serialize users into and deserialize users out of the session.  In a
// production-quality application, this would typically be as simple as
// supplying the user ID when serializing, and querying the user record by ID
// from the database when deserializing.  However, due to the fact that this
// example does not have a database, the complete Facebook profile is serialized
// and deserialized.
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

/* GET /login
 *
 * This route prompts the user to log in.
 *
 * The 'login' view renders an HTML page, which contain a button prompting the
 * user to sign in with Keyp.  When the user clicks this button, a request
 * will be sent to the `GET /login` route.
 */
router.get("/login", function (req, res, next) {
  res.render("login");
});

/* GET /login/keyp
 *
 * This route redirects the user to Keyp, where they will authenticate.
 *
 * Signing in with Keyp is implemented using OAuth 2.0.  This route initiates
 * an OAuth 2.0 flow by redirecting the user to Keyp's identity server at
 * 'https://app.usekeyp.com'.  Once there, Keyp will authenticate the user
 * and obtain their consent to release identity information to this app.
 *
 * Once Keyp has completed their interaction with the user, the user will be
 * redirected back to the app at `GET /redirect/keyp`.
 */
router.get("/login/keyp", passport.authenticate("oauth2"));

/*
    This route completes the authentication sequence when Keyp redirects the
    user back to the application.  When a new user signs in, a user account is
    automatically created and their Keyp account is linked.  When an existing
    user returns, they are signed in to their linked account.
*/
router.get(
  "/redirect/keyp",
  passport.authenticate("oauth2", {
    successReturnToOrRedirect: "/",
    failureRedirect: "/login",
  })
);

module.exports = router;
