import dotenv from 'dotenv';
//we need to run the config func to load the contents of .env file
import connectDB from './src/db/index.js';
import app from './src/app.js';
dotenv.config();
const port = process.env.PORT || 8000;
connectDB()
    .then(() => {
        app.listen(port, () => {
            console.log(`WorkDen is listening on https://localhost:${port}`);
        });

    })
    .catch((err) => {
        console.log("MongoDB connection failed: ", err);
        process.exit(1);
    });
    


