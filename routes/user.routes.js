import express from "express";
import { login, passwordResetLink, register, verify, verifyPasswordReset } from "../controller/user.controller.js";

const router = express.Router();

router.post('/register', register)
router.post('/login', login)
router.get('/verify/:token', verify)
router.post('/password-reset', passwordResetLink)
router.post('/password-reset/:token', verifyPasswordReset)

export default router;