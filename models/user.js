const { Schema, model } = require("mongoose");
const Joi = require("joi");

const handleMongooseError = require("../helpers/handleMongooseError");

const emailRegExp = /^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$/;

const userSchema = new Schema(
  {
    name: {
      type: String,
      required: [true, "Name is required"],
    },
    email: {
      type: String,
      match: [emailRegExp, "Enter a valid email"],
      required: [true, "Email is required"],
      unique: true,
    },
    password: {
      type: String,
      minLength: [6, "The password should have at least 6 symbols"],
      required: [true, "Set password for user"],
    },
    avatarURL: {
      type: String,
      required: true,
    },
    token: String,
  },
  { versionKey: false, timestamps: true }
);

userSchema.post("save", handleMongooseError);

const User = model("user", userSchema);

const registerSchema = Joi.object({
  name: Joi.string().required(),
  email: Joi.string().pattern(new RegExp(emailRegExp)).required(),
  password: Joi.string()
    .min(6)
    .required()
    .messages({ "string.min": "The password should have at least 6 symbols" }),
});

const loginSchema = Joi.object({
  email: Joi.string().pattern(new RegExp(emailRegExp)).required(),
  password: Joi.string()
    .min(6)
    .required()
    .messages({ "string.min": "The password has at least 6 symbols" }),
});

const schemas = {
  registerSchema,
  loginSchema,
};

module.exports = { User, schemas };
