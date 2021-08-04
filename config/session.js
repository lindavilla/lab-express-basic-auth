require('dotenv').config();

const MongoStore = require('connect-mongo');

const session = {
    store: MongoStore.create({
      mongoUrl: `mongodb://localhost/${process.env.DB_NAME}`,
      ttl: 24 * 60 * 60,
    }),
    secret: process.env.SESS_SECRET,
    resave: true,
    saveUninitialized: true,
    cookie: {
      maxAge: 24 * 60 * 60 * 1000,
    },
  };

module.exports = session;