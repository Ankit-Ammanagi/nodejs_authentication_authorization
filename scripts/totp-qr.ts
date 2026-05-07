import QRcode from "qrcode";

const otpAuthUrl = process.argv[2];

if (!otpAuthUrl) {
  throw new Error("Please provide an OTP Auth URL as a command line argument.");
}

async function generateQRCode(url: string) {
  try {
    await QRcode.toFile("totp.png", url);
  } catch (err) {
    console.error("Error generating QR code:", err);
    process.exit(1);
  }
}

generateQRCode(otpAuthUrl);
