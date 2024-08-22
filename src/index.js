import express from 'express';
import mongoose from 'mongoose';
import User from './model/user.js';
import bcrypt from 'bcrypt';
import passport from 'passport';
import LocalStrategy from 'passport-local';
import session from 'express-session';
import MongoStore from 'connect-mongo';

const app = express();
const port = process.env.PORT;

app.use(express.json());

try {
  await mongoose.connect(process.env.MONGO_DB);
} catch (err) {
  console.error('Failed to connect to MongoDB:', err.message);
  process.exit(1);
}

app.use(
  session({
    secret: process.env.JWT_KEY,
    store: MongoStore.create({
      mongoUrl: process.env.MONGO_DB,
      collectionName: 'sessions',
    }),
  })
);

app.use(passport.session());

passport.use(
  'local',
  new LocalStrategy(async function verify(username, password, cb) {
    const user = await User.findOne({
      username: username,
    });

    if (user) {
      const pass = user.password;
      const compare = await bcrypt.compare(password, pass);

      if (!compare) {
        return cb(null, false, { message: 'Incorrect username or password.' });
      }

      return cb(null, user.toObject());
    } else {
      return cb('User does not exists.');
    }
  })
);

passport.serializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, {
      id: user._id.toString(),
      username: user.username,
      email: user.email,
    });
  });
});

passport.deserializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, user);
  });
});

app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res
      .status(400)
      .json({ error: 'You must provide username, email and password' });
  }

  const hashedPass = await bcrypt.hash(password, 10);

  const user = new User({
    username,
    email,
    password: hashedPass,
  });

  const saved = await user.save();

  if (saved) {
    req.logIn(
      {
        username,
        email,
        _id: user._id,
      },
      () => {
        res.redirect('/');
      }
    );
  } else {
    res.status(500).json({ error: 'Something went wrong. Please try again.' });
  }
});

app.post('/login', passport.authenticate('local'), async (req, res) => {
  return res.status(200).json(req.session.passport.user);
});

const loggedIn = (req, res, next) => {
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    return res.status(403).json({ error: 'Access denied' });
  }
  next();
};

app.get('/', loggedIn, (req, res) => {
  return res.json(req.user);
});

app.post('/logout', (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.json({ message: 'You are logged out succesfully.' });
  });
});

app.listen(port, () => {
  console.log(`App listening on port ${port}...`);
});
