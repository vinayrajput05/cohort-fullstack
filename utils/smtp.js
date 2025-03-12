import nodemailer from 'nodemailer'

class Smtp {
    #transporter;

    constructor() {
        this.#transporter = nodemailer.createTransport({
            host: process.env.MAILTRAP_HOST,
            port: process.env.MAILTRAP_PORT,
            secure: false, // true for port 465, false for other ports
            auth: {
                user: process.env.MAILTRAP_USER,
                pass: process.env.MAILTRAP_PASSWORD,
            },
        });
    }

    async sendVerification(user) {
        const verificationUrl = `${process.env.BASE_URL}/api/v1/users/verify/${user.verificationToken}`
        const info = await this.#transporter.sendMail({
            from: `"Cohort Fullstack " <cohort@fullstack.com>`,  // sender address
            to: user.email, // list of receivers
            subject: "Please Verify Your Account", // Subject line
            html: `<!DOCTYPE html>
                        <html lang="en">
                        <head>
                            <meta charset="UTF-8">
                            <meta name="viewport" content="width=device-width, initial-scale=1.0">
                            <title>Email Verification</title>
                            <style>
                                body {
                                    font-family: Arial, sans-serif;
                                    margin: 0;
                                    padding: 0;
                                    background-color: #f4f4f4;
                                    color: #333;
                                }
                                .email-container {
                                    width: 100%;
                                    max-width: 600px;
                                    margin: 0 auto;
                                    background-color: #fff;
                                    padding: 20px;
                                    border-radius: 8px;
                                    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                                }
                                .email-header {
                                    text-align: center;
                                    padding-bottom: 20px;
                                }
                                .email-header h1 {
                                    margin: 0;
                                    font-size: 24px;
                                    color: #4CAF50;
                                }
                                .email-body {
                                    font-size: 16px;
                                    line-height: 1.5;
                                }
                                .email-body p {
                                    margin: 15px 0;
                                }
                                .verify-button {
                                    display: inline-block;
                                    padding: 10px 20px;
                                    background-color: #4CAF50;
                                    color: white;
                                    text-decoration: none;
                                    border-radius: 5px;
                                    font-size: 16px;
                                    margin-top: 20px;
                                }
                                .alternative-link {
                                    margin-top: 15px;
                                    font-size: 14px;
                                }
                                .footer {
                                    text-align: center;
                                    margin-top: 30px;
                                    font-size: 14px;
                                    color: #888;
                                }
                                .footer a {
                                    color: #4CAF50;
                                    text-decoration: none;
                                }
                            </style>
                        </head>
                        <body>
                            <div class="email-container">
                                <div class="email-header">
                                    <h1>Welcome to [Your Company Name]</h1>
                                </div>
                                <div class="email-body">
                                    <p>Hello ${user.name},</p>
                                    <p>Thank you for signing up with us. To complete your registration, please click the button below to verify your email address:</p>
                                    <p><a href="${verificationUrl}" class="verify-button">Verify Email</a></p>
                                    <p class="alternative-link">
                                        If the button above doesn't work, you can click the link below to verify your email address:<br>
                                        <a href="${verificationUrl}">${verificationUrl}</a>
                                    </p>
                                    <p>If you did not create an account with us, please ignore this email.</p>
                                </div>
                                <div class="footer">
                                    <p>&copy; 2025 [Your Company Name]. All rights reserved.</p>
                                    <p>Need help? Visit our <a href="[Support Link]">support page</a> for assistance.</p>
                                </div>
                            </div>
                        </body>
                        </html>

                    `,
        });

        console.log("Message sent: %s", info.messageId);
    }

    async sendPasswordResetLink(user) {
        const resetUrl = `${process.env.BASE_URL}/api/v1/users/password-reset/${user.passwordResetToken}`
        const info = await this.#transporter.sendMail({
            from: `"Cohort Fullstack " <cohort@fullstack.com>`,  // sender address
            to: user.email, // list of receivers
            subject: "Password Reset", // Subject line
            html: `<!DOCTYPE html>
                        <html lang="en">
                        <head>
                            <meta charset="UTF-8">
                            <meta name="viewport" content="width=device-width, initial-scale=1.0">
                            <title>Password Reset</title>
                            <style>
                                body {
                                    font-family: Arial, sans-serif;
                                    margin: 0;
                                    padding: 0;
                                    background-color: #f4f4f4;
                                    color: #333;
                                }
                                .email-container {
                                    width: 100%;
                                    max-width: 600px;
                                    margin: 0 auto;
                                    background-color: #fff;
                                    padding: 20px;
                                    border-radius: 8px;
                                    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                                }
                                .email-header {
                                    text-align: center;
                                    padding-bottom: 20px;
                                }
                                .email-header h1 {
                                    margin: 0;
                                    font-size: 24px;
                                    color: #d9534f;
                                }
                                .email-body {
                                    font-size: 16px;
                                    line-height: 1.5;
                                }
                                .email-body p {
                                    margin: 15px 0;
                                }
                                .reset-button {
                                    display: inline-block;
                                    padding: 10px 20px;
                                    background-color: #d9534f;
                                    color: white;
                                    text-decoration: none;
                                    border-radius: 5px;
                                    font-size: 16px;
                                    margin-top: 20px;
                                }
                                .alternative-link {
                                    margin-top: 15px;
                                    font-size: 14px;
                                }
                                .footer {
                                    text-align: center;
                                    margin-top: 30px;
                                    font-size: 14px;
                                    color: #888;
                                }
                                .footer a {
                                    color: #d9534f;
                                    text-decoration: none;
                                }
                            </style>
                        </head>
                        <body>
                            <div class="email-container">
                                <div class="email-header">
                                    <h1>Password Reset Request</h1>
                                </div>
                                <div class="email-body">
                                    <p>Hello ${user.name},</p>
                                    <p>We received a request to reset your password. Click the button below to reset it:</p>
                                    <p><a href="${resetUrl}" class="reset-button">Reset Password</a></p>
                                    <p class="alternative-link">
                                        If the button above doesn't work, you can use the link below to reset your password:<br>
                                        <a href="${resetUrl}">${resetUrl}</a>
                                    </p>
                                    <p>If you didn't request this, please ignore this email. Your password will remain unchanged.</p>
                                </div>
                                <div class="footer">
                                    <p>&copy; 2025 [Your Company Name]. All rights reserved.</p>
                                    <p>Need help? Visit our <a href="[Support Link]">support page</a> for assistance.</p>
                                </div>
                            </div>
                        </body>
                        </html>
                    `,
        });

        console.log("Message sent: %s", info.messageId);
    }
}

const smtp = new Smtp();

export default smtp;