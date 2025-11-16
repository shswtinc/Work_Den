import { asyncHandler } from "../utils/asyncHandlers.js";
import { APIError } from "../utils/api-error.js";
import { User } from "../models/user.models.js";
import { APIResponse } from "../utils/api-response.js";
import { emailVerificationMail, sendMail,forgotPasswordMail } from '../utils/email.js';
import jwt from "jsonwebtoken";
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
    if ([fullName, email, username, password].some(field => field == null || String(field).trim() === "")) {
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

const login = asyncHandler(async (req, res) => {
    const { email, password, username } = req.body;
    if (!username || !email) {
        throw new APIError(400, "Username or email is required")
    }
    const user = await User.findOne({ email })//here we found if user exists or not?
    if (!user) {//logic for not existing
        throw new APIError(400, "User does not exist")
    }
    //now here we will write logic for if user exists, then we need ->
    //check password
    const isPasswordValid = await user.isPasswordCorrect(password);
    if (!isPasswordValid) {
        throw new APIError(400, "Password is invalid");
    }
    //upon pass correct, generate all the tokens
    const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(user._id);
    //just storing email and password
    const loggedInUser = await User.findById(user._id).select("-password -refreshToken -emailVerificationToken -emailVerificationExpiry");
    const options = {
        httpOnly: true,
        secure: true,
    }
    return res
        .status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", refreshToken, options)
        .json(
            new APIResponse(
                200,
                {
                    user: loggedInUser,
                    accessToken,
                    refreshToken,
                },
                "User logged in successfully"
            )
        )
});

const logoutUser = asyncHandler(async (req, res) => {
    await User.findByIdAndUpdate(
        req.user_id,
        {
            $set: {
                refreshToken: "",
            },
        },
        {
            new: true
        },
    );
    const options = {
        httpOnly: true,
        secure: true
    };
    return res
        .status(200)
        .clearCookie("accessToken", options)
        .clearCookie("refreshToken", options)
        .json(new APIResponse(200, {}, "User logged out"));


})
const getCurrentUser = asyncHandler(async (req, res) => { //this is gonna be GET
    return res
        .status(200)
        .json(
            new APIResponse(
                200, req.user, 'User fetching done successfully'
            )
        );
});
const changePassword = asyncHandler(async (req, res) => {//POST
    //rememeber that the usr is alr login, hence the user has already proved for being loggedIn
    const { oldPassword, newPassword } = req.body
    const user = await User.findById(req.user._id);
    const isPasswordValid = await user.isPasswordCorrect(oldPassword);
    if (!isPasswordValid) {
        throw new APIError(
            400,
            "FAILED: Entered password is incorrect "
        )
    }
    user.password = newPassword
    user.refreshToken = undefined;
    await user.save({ validateBeforeSave: false });
    const options = { httpOnly: true, secure: true };
    res.clearCookie('accessToken', options)
    res.clearCookie('refreshToken', options)
    
    return res
        .status(200)
        .json(new APIResponse(
            200,
            {},
            "SUCCESS: Password changed!"
        ))

});

const verifyEmail = asyncHandler(async (req, res) => {
    //we took the incoming token from the URL
    const { verificationToken } = req.params //destructuring done , look under req.params object and bring me verificationToken
    if (!verificationToken) {
        throw new APIError(400, "Email token is missing")
    }
    //hashed it
    const hashedToken = crypto
        .createHash("sha256")
        .update(verificationToken)
        .digest("hex")
    //find in the db , the token -> hashedtoken and tokenExpiry should be in future , hence $gt:Date.now()
    const user = await User.findOne({
        emailVerificationToken: hashedToken,
        emailVerificationExpiry: { $gt: Date.now() }
    });
    if (!user) {
        throw new APIError(400, "Verification link is invalid or expired");
    }
    //if user exists...
    user.isEmailVerified = true
    user.emailVerificationToken = undefined //single use , after verfication removed from DB
    user.emailVerificationExpiry = undefined //same
    await user.save({ validateBeforeSave: false });
    return res
        .status(200)
        .json(new APIResponse(200, "Email verified successfully"));
});
const resendEmailVerification = asyncHandler(async (req, res) => {
    //get user first
    const user = await User.findById(req.user?._id)
    if (!user) {
        throw new APIError(404, "User does not exist");
    }
    //check if email already verified
    if (user.isEmailVerified) {
        throw new APIError(409, "User already verified");
    }
    //generate new token
    const { hashedToken, unHashedToken, tokenExpiry } = user.generateTemporaryToken();
    //save, hashedTok and token expiry in DB and send unHasedTOk with email
    user.emailVerificationToken = hashedToken;
    user.emailVerificationExpiry = tokenExpiry;
    await user.save({ validateBeforeSave: false });
    //send email
    await sendMail({
        email: user?.email,
        subject: "Resend Verification link",
        mailGenContent: emailVerificationMail(
            user.username,
            `${req.protocol}://${req.get("host")}/api/v1/users/verify-email/${unHashedToken}`
        )
    });
    return res
        .status(200)
        .json(new APIResponse(
            200,
            {},
            "SUCCESS: Verification link sent"
        ));

})
const refreshAccessToken = asyncHandler(async (req, res) => {
    //extract the token
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken
    if (!incomingRefreshToken) {
        throw new APIError(401, "Unauthorized access");
    }
    try {
        //decode the token
        const decodeToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET);
        //get user  
        const user = await User.findById(decodeToken?._id)
        if (!user) {
            throw new APIError(401, "Invalid refresh token");
        }
        if (incomingRefreshToken !== user?.refreshToken) {
            throw new APIError(401, "Refresh token expired or used");
        }
        const options = {
            httpOnly: true,
            secure: true
        }

        const {accessToken, refreshToken:newRefreshToken}= await user.generateAccessAndRefreshTokens(user?._id)
        return res
            .status(200)
            .cookie("accessToken", accessToken, options)
            .cookie("refreshToken", newRefreshToken, options)
            .json(new APIResponse(
                200,
                {accessToken, refreshToken:newRefreshToken},
                "Access token refreshed successfully"
        ))
    } catch (error) {
             throw new APIError(401, "FAILED: Aceess token INVALID");
    }
});
const forgotPassword = asyncHandler(async (req, res) => {
    //get the email look for it in DB, and send user email with the 'change-password' link 
    const { email } = req.body;
    if (!email) {
        throw new APIError(404, "Email is required");
    }
    const user = await User.findOne({ email });//here we are finding user by email
    if (!user || !user.isEmailVerified) {
        throw new APIError(404, "FAILED: User not found or email not registered");
    }
    //generate and save tokens
    const {
        unHashedToken,
        hashedToken,
        tokenExpiry
    } = user.generateTemporaryToken();
    //save logic
    user.forgotPasswordToken = hashedToken
    user.forgotPasswordExpiry = tokenExpiry
    await user.save({ validateBeforeSave: false });
    //send the email
    const passwordResetURL = `${req.protocol}://${req.get("host")}/api/v1/users/reset-password/${unHashedToken}`;
    await sendMail({
        email: user?.email,
        subject: "Reset your password",
        mailGenContent: forgotPasswordMail(
            user.username,passwordResetURL
        )
    })
    return res
        .status(200)
        .json(new APIResponse(
            200,
            {},
            "SUCCESS: Email sent, create new password"
        ));
});
const resetForgotPassword = asyncHandler(async (req, res) => {
    const { newPassword } = req.body;
    const { resetToken } = req.params;
    const hashedToken = crypto
        .createHash("SHA256")
        .update(resetToken)
        .digest("hex")
    const user = User.findOne({
        forgotPasswordToken: resetToken,
        forgotPasswordExpiry:{$gt:Date.now()}
    })
    if (!user) {
        throw new APIError(
            489, "Token is invalid or expired"
        );
    };
    user.forgotPasswordExpiry = undefined
    user.forgotPasswordToken = undefined
    user.password = newPassword //hashed by 'pre' hook , this is done by mongoose , on seeing the save() method run 
    await user.save({ validateBeforeSave: false });
    return res
        .status(200)
        .json(new APIResponse(
        200,{},"SUCCESS : Password reset"
    ))
});
export {
    registerUser,
    generateAccessAndRefreshTokens,
    login,
    logoutUser,
    getCurrentUser,
    changePassword,
    verifyEmail,
    resendEmailVerification,
    refreshAccessToken,
    forgotPassword,
    resetForgotPassword
};
