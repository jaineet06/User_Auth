import express from 'express'
import cors from 'cors'
import 'dotenv/config'
import cookieParser from 'cookie-parser'
import connectDB from './config/mongoDB.js'
import authRouter from './routes/authRoute.js'
import userRoute from './routes/userRoute.js'

connectDB()

const app = express()
const port = process.env.PORT || 4000

const allowedOrigins = ['http://localhost:5173']

app.use(express.json())
app.use(cookieParser())
app.use(cors({origin: allowedOrigins, credentials: true}))


// Api endpoints
app.get('/', (req, res) => {
    res.send("Api Working")
})

app.use('/api/auth', authRouter)
app.use('/api/user', userRoute)



app.listen(port, () => {
    console.log("Serving on port: " + port);
})