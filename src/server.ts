import app from "./app";
import dotenv from "dotenv";
import { connectDB } from "./lib/db";
import http from "http";

dotenv.config();


async function startServer() {
    await connectDB();

    const server = http.createServer(app);

    server.listen(process.env.PORT || 3000, () => {
        console.log(`Server is now listening to port ${process.env.PORT}`);
    })
}

startServer().catch((error) => {
    console.error("Failed to start server:", error);
    process.exit(1);
});
