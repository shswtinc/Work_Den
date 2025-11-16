import { Router } from 'express';
import { registerUser } from '../controllers/auth.controller.js';
import { userChangeCurrentPasswordValidator, userForgotPasswordValidator, userRegisterValidator ,  userResetForgotPasswordValidator } from '../validators/index.js';
import { validate } from '../middlewares/validator.middleware.js';
import { login } from '../controllers/auth.controller.js';
import { userLoginValidator } from '../validators/index.js';
import { logoutUser } from '../controllers/auth.controller.js';
import { verifyJWT } from '../middlewares/auth.middleware.js';
import { getCurrentUser } from '../controllers/auth.controller.js';
import { changePassword } from '../controllers/auth.controller.js';
import { verifyEmail } from '../controllers/auth.controller.js';
import { resendEmailVerification } from '../controllers/auth.controller.js';
import { refreshAccessToken } from '../controllers/auth.controller.js';
import { forgotPassword } from '../controllers/auth.controller.js';
import { resetForgotPassword } from '../controllers/auth.controller.js';
const router = Router();
router.route("/register").post(userRegisterValidator(), validate, registerUser);//so we extracted error and gave where we collected it
router.route("/login").post(userLoginValidator(), validate, login);
router.route("/logout").post(verifyJWT,logoutUser);
router.route("/current-user").get(verifyJWT, getCurrentUser);
router.route("/change-password").get( verifyJWT, userChangeCurrentPasswordValidator(),validate, changePassword);
router.route("/verify-email/:verificationToken").get(verifyEmail);
router.route("/resend-email-verification").post(verifyJWT, resendEmailVerification);
router.route("/refresh-token").post(refreshAccessToken);
router.route("/forgot-password").post(userForgotPasswordValidator(), validate, forgotPassword);
router.route("/reset-password/:resetToken").post( userResetForgotPasswordValidator(),validate, resetForgotPassword)
export default router