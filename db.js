var sqlite3 = require("sqlite3");
var mkdirp = require("mkdirp");

mkdirp.sync("./var/db");

var db = new sqlite3.Database("./var/db/todos.db");

db.serialize(function () {
  db.run(
    "CREATE TABLE IF NOT EXISTS users ( \
    id TEXT PRIMARY KEY, \
    access_token TEXT, \
    email TEXT \
    )"
  );

  db.run(
    "CREATE TABLE IF NOT EXISTS federated_credentials ( \
    id INTEGER PRIMARY KEY, \
    user_id TEXT NOT NULL, \
    provider TEXT NOT NULL, \
    UNIQUE (provider, user_id) \
    )"
  );

  db.run(
    "CREATE TABLE IF NOT EXISTS todos ( \
    id INTEGER PRIMARY KEY, \
    owner_id TEXT NOT NULL, \
    title TEXT NOT NULL, \
    completed INTEGER \
  )"
  );
});

module.exports = db;
