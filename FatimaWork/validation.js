import Joi from "joi";
import { patterns, messages } from "./validationPatterns.js";

export const registerSchema = Joi.object({
  name: Joi.string().min(3).max(50).required(),
  email: Joi.string().email().required(),
  password: Joi.string()
    .min(8)
    .pattern(patterns.strongPassword)
    .message(messages.passwordComplexity)
    .required(),
  confirm_password: Joi.string()
    .valid(Joi.ref("password"))
    .required()
    .messages({
      "any.only": messages.confirmPasswordMismatch,
      "any.required": "Confirm Password is required",
    }),
  role: Joi.string().valid("student", "instructor", "admin").default("student"),
});

export const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required(),
});

export const changePasswordSchema = Joi.object({
  currentPassword: Joi.string().required().label("Current Password"),
  newPassword: Joi.string()
    .min(8)
    .required()
    .pattern(patterns.strongPassword)
    .label("New Password")
    .messages({
      "string.pattern.base": messages.passwordComplexity,
    }),
  confirmNewPassword: Joi.string()
    .valid(Joi.ref("newPassword"))
    .required()
    .label("Confirm New Password")
    .messages({
      "any.only": messages.confirmPasswordMismatch,
    }),
});

export const validateCourseCreation = Joi.object({
  title: Joi.string().min(5).max(100).required(),
  description: Joi.string().min(10).max(1000).required(),
  category_id: Joi.number().integer().required(),
  price: Joi.number().min(0).default(0),
  thumbnail_url: Joi.string().uri().optional(),
});

export const validateCourseUpdate = Joi.object({
  title: Joi.string().min(5).max(100),
  description: Joi.string().min(10).max(1000),
  category_id: Joi.number().integer(),
  price: Joi.number().min(0),
  thumbnail_url: Joi.string().uri(),
  is_published: Joi.boolean(),
}).min(1); // At least one field required

export const validate = (schema) => {
  return (req, res, next) => {
    const { error } = schema.validate(req.body, { abortEarly: false });

    if (error) {
      return res.status(400).json({
        success: false,
        message: "Validation error",
        details: error.details.map((detail) => detail.message),
      });
    }

    next();
  };
};

// import Joi from "joi";

// export const registerSchema = Joi.object({
//   name: Joi.string().min(3).max(50).required(),
//   email: Joi.string().email().required(),
//   password: Joi.string()
//     .min(8)
//     .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
//     .message(
//       "Password must contain 1 uppercase, 1 lowercase, 1 number, and 1 special character"
//     )
//     .required(),
//   confirm_password: Joi.string()
//     .valid(Joi.ref("password")) // Must match 'password' field
//     .required()
//     .messages({
//       "any.only": "Passwords do not match",
//       "any.required": "Confirm Password is required",
//     }),
//   role: Joi.string().valid("student", "instructor", "admin").default("student"),
// });
// export const loginSchema = Joi.object({
//   email: Joi.string().email().required(),
//   password: Joi.string().required(),
// });
// export const changePasswordSchema = Joi.object({
//   currentPassword: Joi.string().required().label("Current Password"),
//   newPassword: Joi.string()
//     .min(8)
//     .required()
//     .regex(
//       /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/
//     )
//     .label("New Password")
//     .messages({
//       "string.pattern.base":
//         "Password must contain at least one uppercase, one lowercase, one number and one special character",
//     }),
//   confirmNewPassword: Joi.string()
//     .valid(Joi.ref("newPassword"))
//     .required()
//     .label("Confirm New Password")
//     .messages({ "any.only": "Passwords do not match" }),
// });
// export const validateCourseCreation = Joi.object({
//   title: Joi.string().min(5).max(100).required(),
//   description: Joi.string().min(10).max(1000).required(),
//   category_id: Joi.number().integer().required(),
//   price: Joi.number().min(0).default(0),
//   thumbnail_url: Joi.string().uri().optional(),
// });

// export const validateCourseUpdate = Joi.object({
//   title: Joi.string().min(5).max(100),
//   description: Joi.string().min(10).max(1000),
//   category_id: Joi.number().integer(),
//   price: Joi.number().min(0),
//   thumbnail_url: Joi.string().uri(),
//   is_published: Joi.boolean(),
// }).min(1); // At least one field required
// export const validate = (schema) => {
//   return (req, res, next) => {
//     const { error } = schema.validate(req.body, { abortEarly: false });

//     if (error) {
//       return res.status(400).json({
//         success: false,
//         message: "Validation error",
//         details: error.details.map((detail) => detail.message),
//       });
//     }

//     next();
//   };
// };
