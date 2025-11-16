import { User } from '../models/user.models.js';
import { asyncHandler } from '../utils/asyncHandlers.js';
import { APIError } from '../utils/api-error.js';
import jwt from 'jsonwebtoken';
export const verifyJWT = asyncHandler(async (req, res, next) => {
    //getting the token from either cookies or the header
    const token = req.cookies?.accessToken || req.header('Authorization')?.replace("Bearer ", "");
    if (!token) {
        throw new APIError(401, "Unauthorized request")
    }
    //token - OK
    try {
        const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
        const user = await User.findById(decodedToken?._id).select("-password -refreshToken -emailVerification -emailVerificationExpiry");
         if (!user) {
             throw new APIError(401, "Invalid access token")
        }
        req.user = user
        next()
    }
    
    catch (error) {
        throw new APIError(401, "Invalid access token")
    }
})