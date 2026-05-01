import express from 'express';
import cookieParser from 'cookie-parser';
import authRoutes from './routes/auth.routes';

const app = express();

app.use(express.json());
app.use(cookieParser());

app.get('/health', (req, res) => {
    res.json({status: 'ok'});
})
app.use('/auth', authRoutes);

export default app;