import { Router } from 'express';
import { registerUser } from '../controllers/auth.controller.js';
import { userRegisterValidator } from '../validators/index.js';
import { validate } from '../middlewares/validator.middleware.js';
import { login } from '../controllers/auth.controller.js';
import { userLoginValidator } from '../validators/index.js';
const router = Router();
router.route("/register").post(userRegisterValidator(), validate, registerUser);//so we extracted error and gave where we collected it
router.route("/login").post(userLoginValidator(),validate, login);
export default router