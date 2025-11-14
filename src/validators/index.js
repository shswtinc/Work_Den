import { body } from 'express-validator';
//here we wil make the validator, i.e extracts the errors
const userRegisterValidator = () => {
    return [
        body("email")
            .trim()
            .notEmpty()
            .withMessage("Email should not be empty")
            .isEmail()
            .withMessage("Email is invalid")
        ,
        body("username")
            .trim()
            .notEmpty()
            .withMessage("Username is required")
            .isLowercase()
            .withMessage("Username should be lowercase")
            .isLength()
            .withMessage("Username must be atleast 3 characters long")
        ,
        body("password")
            .trim()
            .notEmpty()
            .withMessage("password is required")
        ,
        body("fullName").optional().trim(),

    ]
}
const userLoginValidator = () => {
    return [
        body("email")
            .optional()
            .isEmail()
            .withMessage("Email is invalid")
        ,
        body("username")
            .trim()
            .notEmpty()
            .withMessage("Username is required")
        ,
          body("password")
            .trim()
            .notEmpty()
            .withMessage("User password is required")
        ,
    ]
}
export { userRegisterValidator , userLoginValidator };