import 'dotenv/config'
import express from "express";
import cors from 'cors';
import cookieParser from 'cookie-parser'
import dbConnect from './utils/db.js';

// Routes
import userRoutes from './routes/user.routes.js'


const port = process.env.PORT || 4000;

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(cors({
    'origin': 'http://127.0.0.1:3000',
    'allowedHeaders': ['Content-Type'],
    'methods': ['GET', "POST"],
    'credentials': true,
}))
dbConnect();

app.use('/api/v1/users', userRoutes)

app.listen(port, (err) => {
    if (err) {
        console.log('fail to start');
        return;
    }
    console.log(`Server started on http:/127.0.0.1:${port}`);
})