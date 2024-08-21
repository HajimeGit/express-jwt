import express from 'express';
import jwt from 'jsonwebtoken';
import mongoose from 'mongoose';
import User from './model/user.js';
import bcrypt from 'bcrypt';

const app = express();
const port = process.env.PORT;

try {
  await mongoose.connect(process.env.MONGO_DB);
} catch (err) {
  console.error('Failed to connect to MongoDB:', err.message);
  process.exit(1);
}

app.use(express.json());

const key = process.env.JWT_KEY;

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

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res
      .status(400)
      .json({ error: 'You must provide username, email and password' });
  }

  const user = await User.findOne({
    username: username,
  });

  if (user) {
    const pass = user.password;
    const compare = await bcrypt.compare(password, pass);

    if (compare) {
      const token = jwt.sign(
        {
          username: username,
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
  }

  return res.status(401).json({ error: 'Email or password is wrong.' });
});

app.get('/protected', (req, res) => {
  let token = req.header('Authorization');

  if (token) {
    token = token.replace(/^Bearer\s+/, '');

    try {
      jwt.verify(token, key);
      return res.status(200).json({ message: 'Protected route accesed' });
    } catch (e) {
      return res.status(401).json({ err: e.message });
    }
  }

  return res.status(401).json({ err: 'Access denied.' });
});

app.listen(port, () => {
  console.log(`App listening on port ${port}...`);
});
