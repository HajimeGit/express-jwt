import mongoose from 'mongoose';

const { Schema, model } = mongoose;

const accountScheme = new Schema({
  userId: {
    type: Schema.Types.ObjectId,
    ref: 'user',
    required: true,
  },
  provider: String,
  subject: String,
});

const Account = model('account', accountScheme);

export default Account;
