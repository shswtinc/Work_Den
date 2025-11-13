import { getAboutPage } from "../controllers/about.controllers.js";
import { Router } from "express";
const router = Router();
router.route("/about").get(getAboutPage);
export default router;