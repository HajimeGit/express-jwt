import mongoose from 'mongoose';

const { Schema, model } = mongoose;

const userScheme = new Schema({
  username: String,
  email: String,
});

const User = model('user', userScheme);
export default User;
