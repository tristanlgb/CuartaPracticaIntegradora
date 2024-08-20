const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const UserSchema = new Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: 'user' },
  documents: [
    {
      name: { type: String },
      reference: { type: String },
    }
  ],
  last_connection: { type: Date }
});

module.exports = mongoose.model('User', UserSchema);