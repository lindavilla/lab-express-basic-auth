const { Schema, model } = require("mongoose");

const userSchema = new Schema({
  username: {
    type: String,
    unique: true,
    required: [true, 'username is required']
  },
  hashedPassword: {
    type: String,
    required: [true, 'password is required']
  } 
});

const User = model("User", userSchema);

module.exports = User;
