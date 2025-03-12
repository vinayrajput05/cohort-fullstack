import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken';
import User from "../model/User.model.js";
import crypto from 'crypto';
import smtp from "../utils/smtp.js";

const register = async (req, res) => {
    try {
        const { name, email, password } = req.body;
        // validate
        if (!name || !email || !password) {
            res.status(406).json({ 'message': 'All fields required' })
            return;
        }

        // check is not exist in db
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            res.status(406).json({ 'message': 'User already exist' })
            return;
        }

        // store in db
        const user = await User.create({ email, name, password });

        // store and send verification
        const now = new Date();
        const token = crypto.randomBytes(32).toString('hex');
        user.verificationToken = token
        user.verificationTokenExpire = now.setTime(now.getTime() + (10 * 60 * 1000)); // m * s * ms
        await user.save();
        smtp.sendVerification(user);

        res.send({
            'message': 'Account created successfully',
            'user': user
        })
        // success
    } catch (error) {
        res.status(401).json({ 'message': 'Fail to create account', 'error': error })
    }
}

const verify = async (req, res) => {
    try {
        const { token } = req.params;
        if (!token) {
            res.status(401).json({ 'message': 'Invalid token', });
            return;
        }
        const user = await User.findOne({ verificationToken: token });

        if (!user) {
            res.status(401).json({ 'message': 'Invalid token', });
            return;
        }
        const now = new Date();
        const expire = user.verificationTokenExpire;

        if (expire.getTime() < now.getTime()) {
            // Send New Token
            // store and send verification
            const token = crypto.randomBytes(32).toString('hex');
            user.verificationToken = token
            user.verificationTokenExpire = now.setTime(now.getTime() + (10 * 60 * 1000)); // m * s * ms
            await user.save();
            smtp.sendVerification(user);
            res.status(401).json({ 'message': 'Token expired! New token send', });
            return;
        }

        if (user.verificationToken !== token) {
            res.status(401).json({ 'message': 'Invalid token', });
            return;
        }
        user.isVerified = true;
        // user.verificationToken = undefined; // remove from document
        // user.verificationToken = null; // exist in document with null value
        user.verificationToken = '';
        user.verificationTokenExpire = ''
        await user.save();

        res.send({
            'message': 'Verify successfully',
        })
    } catch (error) {
        res.status(401).json({ 'message': 'Fail to verify account', 'error': error })
    }
}

/*
1. Validate
2. Check in db
3. Validate password
4. If valid then create jwt token
*/
const login = async (req, res) => {
    try {
        const { email, password } = req.body;
        // validate
        if (!email || !password) {
            res.status(401).json({ 'message': 'All fields are required.' })
            return;
        }

        const user = await User.findOne({ email });
        if (!user) {
            res.status(404).json({ 'message': 'Invalid credentials' })
            return;
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            res.status(404).json({ 'message': 'Invalid credentials' })
            return;
        }

        if (user.isVerified) {
            res.status(401).json({ 'message': 'Please verify your account' })
            return;
        }

        const token = jwt.sign({ id: user._id, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '2 days' }
        )

        const cookieOptions = {
            httpOnly: true,
            secure: true,
            maxAge: 24 * 60 * 60 * 1000
        }
        res.cookie('token', token, cookieOptions)

        res.status(200).json({
            status: true,
            message: 'Login successful',
            user: {
                id: user._id,
                name: user.name,
                role: user.role
            }
        })

    } catch (error) {
        res.status(401).json({ 'message': 'Fail to login', 'error': error })
    }
}

const passwordResetLink = async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) {
            res.status(401).json({ 'message': 'Email is required', });
            return;
        }
        const user = await User.findOne({ email });

        if (!user) {
            res.status(404).json({ 'message': 'User not found', });
            return;
        }
        const now = new Date();
        const token = crypto.randomBytes(32).toString('hex');
        user.passwordResetToken = token
        user.passwordResetTokenExpire = now.setTime(now.getTime() + (10 * 60 * 1000)); // m * s * ms
        await user.save();
        smtp.sendPasswordResetLink(user);
        res.send({
            'message': 'Password reset link send successfully',
        });
    } catch (error) {
        res.status(401).json({ 'message': 'Fail to send password reset link', 'error': error })
    }
}

const verifyPasswordReset = async (req, res) => {
    try {
        const { token } = req.params;
        const { password } = req.body;

        if (!token) {
            res.status(401).json({ 'message': 'Invalid token', });
            return;
        }

        if (!password) {
            res.status(401).json({ 'message': 'New password is required', });
            return;
        }

        const user = await User.findOne({ passwordResetToken: token });

        if (!user) {
            res.status(401).json({ 'message': 'Invalid token', });
            return;
        }
        const now = new Date();
        const expire = user.passwordResetTokenExpire;

        if (expire.getTime() < now.getTime()) {
            res.status(401).json({ 'message': 'Token expired!', });
            return;
        }

        if (user.passwordResetToken !== token) {
            res.status(401).json({ 'message': 'Invalid token', });
            return;
        }
        user.password = password;
        user.passwordResetToken = '';
        user.passwordResetTokenExpire = ''
        await user.save();

        res.send({
            'message': 'Password reset successfully',
        })
    } catch (error) {
        res.status(401).json({ 'message': 'Fail to update password', 'error': error })
    }
}

export { register, login, verify, passwordResetLink, verifyPasswordReset }