import { text } from 'express';
import Mailgen from 'mailgen';
import nodeMailer from 'nodemailer';

const sendMail = async (options) => {
    // normalize recipient
    const to = options?.email || options?.to || process.env.TEST_RECEIVER_EMAIL;
    if (!to) {
        throw new Error("No recipient specified for sendMail (options.email/options.to or TEST_RECEIVER_EMAIL)");
    }

    const mailGenerator = new Mailgen({
        theme: "default",
        product: {
            name: "Work Den",
            link: "https://workden.com",
        }
    });

    const emailBody = mailGenerator.generate(options.mailGenContent);
    const emailText = mailGenerator.generatePlaintext(options.mailGenContent);

    const smtpPort = Number(process.env.MAILTRAP_SMTP_PORT) || 2525;

    const transport = nodeMailer.createTransport({
        host: process.env.MAILTRAP_SMTP_HOST,
        port: smtpPort,
        secure: smtpPort === 465,
        auth: {
            user: process.env.MAILTRAP_SMTP_USERNAME,
            pass: process.env.MAILTRAP_SMTP_PASSWORD
        }
    });

    try {
        await transport.verify();
        const mail = {
            from: options.from || "mail.workden@sasa.com",
            to, // validated above
            subject: options.subject || "No subject",
            text: emailText,
            html: emailBody
        };
        console.log("Sending email envelope:", { from: mail.from, to: mail.to, subject: mail.subject });
        await transport.sendMail(mail);
        console.log("Email sent to:", to);
    } catch (error) {
        console.error("Error sending email. Check Mailtrap credentials and network:", error);
        throw error;
    }
};

const emailVerificationMail = (username, verificationURL) => {
    return {
        body: {
            name: username,
            intro: `Welcome to WorkDen! We're very excited to have you on board.`,
            action: {
                instructions: `To get started with WorkDen, click here:`,
                button: {
                    color: `#59FF67`,
                    text: `Click to continue`,
                    link: verificationURL
                }
            },
            outro: `Need help, or have questions? Just reply to this email, we'd love to help.`
        }
    };
}
const forgotPasswordMail = (username, passwordResetURL) => {
    return {
        body: {
            name: `Hi! ${username}`,
            intro: `You have received this email because a password reset request for your account was received.`,
            action: {
                instructions: `Click the button to reset your password`,
                button: {
                    color: `#5993FF`,
                    text: `Reset your password`,
                    link: passwordResetURL,
                }
            }
        }
    }
}
export {
    emailVerificationMail,
    forgotPasswordMail,
    sendMail
};