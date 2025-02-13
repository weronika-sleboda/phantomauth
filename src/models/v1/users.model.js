import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  email: { 
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true
  },
  password: {
    type: String,
    required: true,
  },
  token: {
    type: String,
    default: null
  },
  twoFAsecret: {
    type: String,
    default: null
  },
  twoFAEnabled: {
    type: Boolean,
    default: false
  }
});

export const User = mongoose.model('User', userSchema);