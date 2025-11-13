import express from 'express';
import cors from 'cors';
import healthCheckRouter from './routes/healthcheck.routes.js';
import homeRouter from './routes/home.routes.js';
import aboutRouter from './routes/about.routes.js';
import authRouter from './routes/auth.routes.js';

const app = express();
app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ extended: true, limit: "16kb" }));
app.use(cors({
    origin: process.env.CORS_ORIGIN,
    credentials: true,
    optionsSuccessStatus: 204,
}));
app.use('/api/v1/auth',authRouter);
app.use("/api/v1/healthcheck", healthCheckRouter);
app.use("/", homeRouter);
app.use("/", aboutRouter);
export default app;