import { asyncHandler } from "../utils/asyncHandlers.js";
import { APIError } from "../utils/api-error.js";
import { User } from "../models/user.models.js";
import { APIResponse } from "../utils/api-response.js";
import { emailVerificationMail, sendMail } from '../utils/email.js';
const generateAccessAndRefreshTokens = async (userId) => {
    //now that we have successfulyy created (or verified the existence) that user exists we need to find the user
    try {
        const user = await User.findById(userId);
        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();
        user.refreshToken = refreshToken;
        await user.save({ validateBeforeSave: false });//NO access token coz no need to save in DB and its stateless
        return { accessToken, refreshToken };
    } catch (error) {
        throw new APIError(500, "Something went worng generating access tokens");
    }
}
const registerUser = asyncHandler(async (req, res) => {
    const { fullName, email, username, password } = req.body || {};
    //now we need to implement a gatekeeper to check whether all the imput fields are entered
    if ([fullName, email, username, password].some(field => field ==null || String(field).trim() === "")) {
        throw new APIError(400, "All fields are required");
    }
    //check if user with same username/email alr exists
    const existedUser = await User.findOne({
        $or: [{ username }, { email }]
    });
    if (existedUser) {
        throw new APIError(409, "User with email or username already exists");
    }
    //if the user does not exist...
    //create the new user object
    const user = await User.create({
        fullName,
        email,
        password,
        username: username.toLowerCase(),
    })
    //verifying whether created or not

    
    const { hashedToken, unHashedToken, tokenExpiry } = user.generateTemporaryToken();
    user.emailVerificationToken = hashedToken;
    user.emailVerificationExpiry = tokenExpiry;
    await user.save({ validateBeforeSave: false });

    await sendMail({
        email: user?.email,
        subject: "Verify your email",
        mailGenContent: emailVerificationMail(
            user.username, `${req.protocol}://${req.get("host")}/api/v1/users/verify-email/${unHashedToken}`,
        )
    });
    const createdUser = await User.findById(user._id).select("-password -refreshToken -emailVerificationToken -emailVerificationExpiry");//finds whether user exists but excludes password
    if (!createdUser) throw new APIError(500, "Something went wrong while trying to register the user");
    return res
        .status(201)
        .json(
            new APIResponse(
                201,
                { user: createdUser },
                "User registered successfully and verification email has been sent"
            )
        )
    
});

export { registerUser };