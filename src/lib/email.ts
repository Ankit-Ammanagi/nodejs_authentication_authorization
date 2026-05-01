import nodemailer from "nodemailer";

function getEnvironmentVariable(value: string[]) : Record<string, string> {
    return value.reduce((acc, curr) => {
        if(!process.env[curr]){
            throw new Error(`Environment variable ${curr} is not set`);
        }
        acc[curr] = process.env[curr] as string;
        return acc;
    }, {} as Record<string, string>)
} 

function createTransporter(host: string, port: number, user: string, pass: string) {
    return nodemailer.createTransport({
        host,
        port,
        secure: false, // true for 465, false for other ports
        auth: {
            user,
            pass
        },
    });
}

export async function sendEmail(to: string, subject: string, html: string) {
    if( !process.env.SMTP_PORT || !process.env.SMTP_USER || !process.env.SMTP_PASS){
        throw new Error("SMTP configuration is not set in environment variables");
    }

    const {SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS} = getEnvironmentVariable(["SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASS"]);

    const transporter = createTransporter(SMTP_HOST, Number(SMTP_PORT), SMTP_USER, SMTP_PASS);

    await transporter.sendMail({
        from: process.env.EMAIL_FROM,
        to,
        subject,
        html,
    });
}
