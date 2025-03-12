import 'dotenv/config'
import mongoose from "mongoose";

const dbConnect = async () => {
    try {
        await mongoose.connect(process.env.MONGO_URI)
        console.log('Db connected');
    } catch (error) {
        console.log('Fail to connect db');
    }
}

export default dbConnect;