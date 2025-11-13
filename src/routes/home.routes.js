import { Router } from 'express';
import { getHomePage } from "../controllers/home.controllers.js";
const router = Router();
router.route("/home").get(getHomePage);
export default router;
