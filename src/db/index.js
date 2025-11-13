import mongoose from "mongoose";
const connectDB = async () => {
    try {
        mongoose.connect(process.env.MONGODB_URI);
        console.log("✅Mongoose connected");
        
    } catch (error) {
        console.log("❌MongoDB connection failed: ", error);
        process.exit(1);
    }
}
export default connectDB;