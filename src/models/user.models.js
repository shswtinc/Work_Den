import mongoose from "mongoose";
import bcrypt from "bcrypt";
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
const { Schema } = mongoose;

const userSchema = new Schema({
    avatar: {
        type: {
            url: String,
            localPath: String,
        },
        default: {
            url: 'https://placehold.co/200x200',
            localPath:"",
        }
    },
    fullName: { type: String, required: true, trim: true, index: true },
    role:{type:String, enum:["admin","project_admin","member"],default:"member"},
    username: {
        type: String,
        required: true,
        index: true,
        unique: true,
        trim: true,
        lowercase:true
    },
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase:true,
    },
    password: {
        type: String,
        required: [true,'Password is required'],
    },
    isEmailVerified: {
        type: Boolean,
        default:false,
    },
    refreshToken: {
       type:String 
    },
    forgotPasswordToken: {
      type:String  
    },
    forgotPasswordExpiry: {
        type:Date
    },
    emailVerificationToken: {
        type:String
    },
    emailVerificationExpiry: {
        type:Date
    }
}, { timestamps: true }); //createdAt updatedAt

//we use pre-save hook
userSchema.pre("save", async function (next) {
    //no hashing needed if password not modified
    if (!this.isModified("password")) {
        return next();
    }
    this.password = await bcrypt.hash(this.password, 10);
    next();
});
userSchema.methods.isPasswordCorrect = async function (password) {
    return await bcrypt.compare(password, this.password);
};
userSchema.methods.generateAccessToken = function () {
    return jwt.sign(
        //payload
        {
        _id: this._id,
        email: this.email,
        username:this.username,
        },
        process.env.ACCESS_TOKEN_SECRET,{expiresIn: process.env.ACCESS_TOKEN_EXPIRY}
    )
};
userSchema.methods.generateRefreshToken = async function () {
    return jwt.sign(
        {
            _id: this._id,
        },
        process.env.REFRESH_TOKEN_SECRET, { expiresIn: process.env.REFRESH_TOKEN_EXPIRY }
    );
};
//GT~ token without data
userSchema.methods.generateTemporaryToken = function () {
    const unHashedToken = crypto.randomBytes(20).toString('hex');
    const hashedToken = crypto
        .createHash("sha256")
        .update(unHashedToken)
        .digest('hex');
const tokenExpiry = Date.now() + (20 * 60 * 1000)
return { unHashedToken, hashedToken, tokenExpiry };
};

export const User = mongoose.model("User", userSchema);