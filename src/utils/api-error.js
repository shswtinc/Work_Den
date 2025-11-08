class APIError extends Error{
    constructor(
        statusCode,
        message = "Something went worng",
        errors = [], //this is done to if we get more error we will push in this array
        stack = ""
    ) {
        super(message);
        this.statusCode = statusCode;
        this.data = null;
        this.message = message;
        this.success = false;
        this.errors = errors;


        if (stack) {
            this.stack = stack;
        } else {
            Error.captureStackTrace(this, this.constructor);
        }
    }
}
