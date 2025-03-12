import mongoose from "mongoose";
import bcrypt from "bcrypt";

const userSchema = new mongoose.Schema({
    name: String,
    email: {
        type: String,
        required: true,
    },
    password: {
        type: String,
        required: true,
    },
    role: {
        type: String,
        enum: ['user', 'admin'],
        default: 'user'
    },
    isVerified: {
        type: Boolean,
        default: false
    },
    verificationToken: String,
    verificationTokenExpire: Date,
    passwordResetToken: String,
    passwordResetTokenExpire: Date,
}, { timestamps: true })

userSchema.pre('save', async function (next) {
    if (this.isModified('password')) {
        try {
            const hashPassword = await bcrypt.hash(this.password, 10);
            this.password = hashPassword;
            next();
        } catch (error) {
            next(error);
        }
    }
})

const User = mongoose.model('User', userSchema);

export default User;