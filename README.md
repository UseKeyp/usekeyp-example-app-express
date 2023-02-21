# todos-express-keyp

This app illustrates how to use [Passport.js](https://www.passportjs.org/) with
[Express](https://expressjs.com/) to sign users in with [Keyp](https://www.usekeyp.com/).
Use this example as a starting point for your own web applications.

## Quick Start

To run this app, clone the repository and install dependencies:

```bash
$ git clone https://github.com/UseKeyp/usekeyp-example-app-express.git
$ npm install
```

This app requires OAuth 2.0 credentials from Keyp, which can be obtained by
[setting up](https://docs.usekeyp.com/oauth)
a client in [Keyp's Developer Portal](https://dev.usekeyp.com).
The redirect URI of the OAuth client should be set to `http://localhost:3000/auth/keyp/callback`.

Once credentials have been obtained, create a `.env` file and add the following
environment variables:

```
KEYP_CLIENT_ID=INSERT_CLIENT_ID_HERE
KEYP_CLIENT_SECRET=INSERT_CLIENT_SECRET_HERE
```

Start the server.

```bash
$ npm start
```

Navigate to [`http://localhost:3000`](http://localhost:3000).

## Overview

This app illustrates how to build a todo app with sign in functionality using
Express, Passport, and the [`Keyp`](https://www.usekeyp.com/)
strategy.

This app is a traditional web application, in which application logic and data
persistence resides on the server. HTML pages and forms are rendered by the
server and client-side JavaScript is not utilized (or kept to a minimum).

This app is built using the Express web framework. Data is persisted to a
[SQLite](https://www.sqlite.org/) database. HTML pages are rendered using [EJS](https://ejs.co/)
templates, and are styled using vanilla CSS.

When a user first arrives at this app, they are prompted to sign in. To sign
in, the user is redirected to Keyp using OpenID Connect. Once authenticated,
a login session is established and maintained between the server and the user's
browser with a cookie.

After signing in, the user can view, create, and edit todo items. Interaction
occurs by clicking links and submitting forms, which trigger HTTP requests.
The browser automatically includes the cookie set during login with each of
these requests.

When the server receives a request, it authenticates the cookie and restores the
login session, thus authenticating the user. It then accesses or stores records
in the database associated with the authenticated user.

## Next Steps

- Check out [Keyp's API documentation](https://docs.usekeyp.com/api) to learn
  how to programmatically transfer tokens, conduct airdrops, access crypto⇔fiat on and off-ramps, get user token balances, and more! 

## License

[The Unlicense](https://opensource.org/licenses/unlicense)

## Credit

Original Google OAuth & Express demo app was created by [Jared Hanson](https://www.jaredhanson.me/) and 
adapted by [Keyp](https://www.usekeyp.com/) to use [Keyp's OAuth process](https://docs.usekeyp.com/oauth).
