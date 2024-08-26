import express from 'express';
import mongoose from 'mongoose';
import User from './model/user.js';
import Account from './model/account.js';
import passport from 'passport';
import Strategy from 'passport-google-oidc';
import session from 'express-session';
import MongoStore from 'connect-mongo';

const app = express();
const port = process.env.PORT;

app.use('/', express.json());

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

const redirectURL = '/oauth2/redirect/google';

passport.use(
  'google',
  new Strategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: 'http://localhost:3000' + redirectURL,
      scope: ['email', 'profile'],
    },
    async (issuer, profile, cb) => {
      const { emails, id, displayName } = profile;

      const account = await Account.findOne({
        provider: issuer,
        subject: id,
      }).populate('userId');

      if (account) {
        return cb(null, account.userId.toObject());
      } else {
        let [email] = emails;
        const user = new User({
          username: displayName,
          email: email.value,
        });

        const result = await user.save();

        if (result) {
          const newAcc = new Account({
            provider: issuer,
            subject: id,
            userId: user._id,
          });

          await newAcc.save();
          return cb(null, user);
        }
      }
    }
  )
);

app.get('/login/oauth2/google', passport.authenticate('google'));
app.get(
  redirectURL,
  passport.authenticate('google', {
    failureRedirect: '/login',
    failureMessage: true,
  }),
  (req, res) => {
    res.redirect('/');
  }
);

passport.serializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, user);
  });
});

passport.deserializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, user);
  });
});

const loggedIn = (req, res, next) => {
  if (!req?.isAuthenticated || !req.isAuthenticated()) {
    return res.status(403).json({ error: 'Access denied' });
  }
  next();
};

app.get('/', loggedIn, (req, res) => {
  return res.json(req.user);
});

app.get('/logout', (req, res) => {
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
