import express from 'express';
import jwt from 'jsonwebtoken';
import mongoose from 'mongoose';
import User from './model/user.js';
import bcrypt from 'bcrypt';
import passport from 'passport';
import { Strategy, ExtractJwt } from 'passport-jwt';
import LocalStrategy from 'passport-local';

const app = express();
const port = process.env.PORT;
const key = process.env.JWT_KEY;

app.use(express.json());

try {
  await mongoose.connect(process.env.MONGO_DB);
} catch (err) {
  console.error('Failed to connect to MongoDB:', err.message);
  process.exit(1);
}

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

passport.use(
  'jwt',
  new Strategy(
    {
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: key,
    },
    async function (jwt_payload, done) {
      const user = await User.findOne({
        username: jwt_payload.username,
      });

      if (user) {
        return done(null, user.toObject());
      } else {
        return done(null, false);
      }
    }
  )
);

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
    const token = jwt.sign(
      {
        username: username,
        email: email,
      },
      key,
      { expiresIn: '1h' }
    );

    res.status(201).json({
      token_type: 'Bearer',
      expires_in: 3599,
      ext_expires_in: 3599,
      access_token: token,
    });
  } else {
    res.status(500).json({ error: 'Something went wrong. Please try again.' });
  }
});

app.post(
  '/login',
  passport.authenticate('local', { session: false }),
  async (req, res) => {
    const user = req.user;

    const token = jwt.sign(
      {
        username: user.username,
        email: user.email,
      },
      key,
      { expiresIn: '1h' }
    );

    return res.status(201).json({
      token_type: 'Bearer',
      expires_in: 3599,
      ext_expires_in: 3599,
      access_token: token,
    });
  }
);

app.get(
  '/profile',
  passport.authenticate('jwt', { session: false }),
  (req, res) => {
    const { _id, password, __v, ...result } = req.user;

    return res.json(result);
  }
);

app.listen(port, () => {
  console.log(`App listening on port ${port}...`);
});
