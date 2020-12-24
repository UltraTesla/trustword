PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users(
  _id INTEGER,
  user BLOB UNIQUE NOT NULL,
  publickey BLOB UNIQUE,
  secretkey BLOB UNIQUE,
  verifykey BLOB UNIQUE,
  signkey BLOB UNIQUE,
  PRIMARY KEY(_id)
);

CREATE TABLE IF NOT EXISTS credentials(
  _id INTEGER,
  userid INTEGER UNIQUE NOT NULL,
  password TEXT NOT NULL,
  PRIMARY KEY(_id),
  FOREIGN KEY(userid) REFERENCES users(_id)
);
