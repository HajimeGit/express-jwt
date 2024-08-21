import express from 'express';
import jwt from 'jsonwebtoken';
import mongoose from 'mongoose';
import User from './model/user.js';
import bcrypt from 'bcrypt';
import passport from 'passport';
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

app.post(
  '/login/password',
  passport.authenticate('local', { session: false }),
  (req, res) => {
    const { password, ...result } = req.user;

    res.json(result);
  }
);

app.listen(port, () => {
  console.log(`App listening on port ${port}...`);
});
