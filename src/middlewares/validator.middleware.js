import { validationResult } from "express-validator";
import { APIError } from "../utils/api-error.js";
//in this humne ,iddleware banaya jo ki error ko collect karega
//this collects the error
export const validate = (req, res, next) => {
    const errors = validationResult(req);
    if (errors.isEmpty()) {
        return next()
    }
    const extractedErrors = [];
    errors.array().map((err) => extractedErrors.push(
        {
            [err.path]:err.msg//this
        },
    ));//ye object tree mein doubt
    throw new APIError
        (422, "Recieved data is not val id", extractedErrors);
}