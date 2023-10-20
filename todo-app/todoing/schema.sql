DROP TABLE IF EXISTS password;
DROP TABLE IF EXISTS user;
DROP TABLE IF EXISTS todo;

CREATE TABLE user (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL,
  user_type TEXT NOT NULL,
  UNIQUE(email) -- This ensures email is unique per authentication provider
);

CREATE TABLE password (
  user_id INTEGER PRIMARY KEY,
  password TEXT NOT NULL,
  salt TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES user (id)
);

CREATE TABLE todo (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  author_id INTEGER NOT NULL,
  created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  title TEXT NOT NULL,
  checked INTEGER NOT NULL, -- 1 = TRUE, 0 = FALSE
  FOREIGN KEY (author_id) REFERENCES user (id)
);
