import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import userModel from '../models/userModel.js'
import transporter from '../config/nodeMailer.js'
import { EMAIL_VERIFY_TEMPLATE, PASSWORD_RESET_TEMPLATE } from '../config/emailTemplate.js'

const register = async (req, res) => {
    const {name, email, password} = req.body

    if(!name || !email || !password){
        return res.json({success: false, message:"Enter all credentials properly!"})
    }

    try {
        
        const isExist = await userModel.findOne({email})
        if(isExist){
            return res.json({success: false, message: "User Already Exist"})
        }

        const hashedPass = await bcrypt.hash(password, 10);

        const user = new userModel({name, email, password: hashedPass})
        await user.save()

        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, {expiresIn: '7d'})

        const options = {
            httpOnly: true, 
            secure: process.env.MODE === 'production',
            sameSite: process.env.MODE === 'production' ? none : true,
            maxAge: 7 * 24 * 60 * 60 * 1000
        }

        res.cookie('token', token, 
            options
        )


        // Sending Welcome Email to the user
        const mailOptions = {
            from: process.env.SMTP_SENDER,
            to: email,
            subject: "Welcome to My Website",
            text: `Your account is created on our website with email ${email}`
        }

        await transporter.sendMail(mailOptions)

        return res.status(200).json({success: true, message: "Registerd Succesfully!"})

    } catch (error) {
        return res.json({success: false, message: error.message})
    }
}

const login = async (req, res) => {
    const {email, password} = req.body

    try {
        
        const user = await userModel.findOne({email})

        if(!user){
            return res.json({success: false, message: "No Account found"})
        }

        const isMatch = await bcrypt.compare(password, user.password)

        if(!isMatch){
            return res.json({success: false, message: "Incorrect Password"})
        }

        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, {expiresIn: '7d'})

        const options = {
            httpOnly: true, 
            secure: process.env.MODE === 'production',
            sameSite: process.env.MODE === 'production' ? none : true,
            maxAge: 7 * 24 * 60 * 60 * 1000
        }

        res.cookie('token', token,
            options
        )

        return res.status(200).json({success: true, message: "Login Succesfully!"})

    } catch (error) {
        return res.json({success: false, message: error.message})
    }
}

const logout = async (req, res) => {
    try {
        res.clearCookie('token', {
            httpOnly: true, 
            secure: process.env.MODE === 'production',
            sameSite: process.env.MODE === 'production' ? none : true,
        })

        return res.json({success: true,  message: "Logout Succesfully!"})
    } catch (error) {
        return res.json({success: false, message: error.message})
    }
}

const sendVerifyOtp = async (req, res) => {
    try {
        const {userId} = req.body;

        const user = await userModel.findById(userId)

        if(user.isAccountVerified){
            return res.json({success: false, message: "Account is Already verified"})
        }

        const otp = String(Math.floor(100000 + Math.random()*900000));

        await userModel.findByIdAndUpdate(
            userId,
            {
                verifyOtp: otp,
                verifyOtpExpireAt: Date.now() + 24 * 60 * 60 * 1000
            },
            { new: true } // Returns updated user
        );

        const mailOptions = {
            from: process.env.SMTP_SENDER,
            to: user.email,
            subject: "Account Verification OTP",
            // text: `Your OTP is ${otp}. Verify your account using this OTP`,
            html: EMAIL_VERIFY_TEMPLATE.replace("{{otp}}", otp).replace("{{email}}", user.email)
        }

        await transporter.sendMail(mailOptions)

        return res.json({success: true, message: "Verification OTP sent on email"})


    } catch (error) {
        return res.json({success: false, message: error.message})
    }
}

const verifyEmail = async (req, res) => {
    const {userId, otp} = req.body

    if(!userId || !otp){
        return res.json({success: false, message: "Missing inputs"})
    }

    try {
        const user = await userModel.findById(userId)

        if(!user){
            return res.json({success: false, message: "User Not found"})
        }

        if(otp === "" || otp !== user.verifyOtp){
            return res.json({success: false, message: "Invalid OTP"})
        }

        if(user.verifyOtpExpireAt < Date.now()){
            return res.json({success: false, message: "OTP Expired"})
        }

        user.isAccountVerified = true
        user.verifyOtp = ''
        user.verifyOtpExpireAt = 0

        await user.save()

        return res.json({ success: true, message: "Account Verified Successfully!" });

    } catch (error) {
        return res.json({success: false, message: error.message})
    }
}

const isAuthenticated = async (req, res) => {
    try {
        return res.json({ success: true, message: "User is Authenticated" });
    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
}

const sendResetOtp = async (req, res) => {
    const {email} = req.body

    if(!email){
        return res.json({ success: false, message: "Email is required" });
    }

    try {
        const user = await userModel.findOne({email})
        if(!user){
            return res.json({ success: false, message: "User Not Found" });
        }

        const otp = String(Math.floor(100000 + Math.random()*900000));

        user.resetOtp = otp
        user.resetOtpExpireAt = Date.now() + 15*60*1000

        await user.save()

        const mailOptions = {
            from: process.env.SMTP_SENDER,
            to: user.email,
            subject: "Password Reset OTP",
            // text: `Your OTP for resetting password is ${otp}. Use this OTP for resetting your password`
            html: PASSWORD_RESET_TEMPLATE.replace("{{otp}}", otp).replace("{{email}}", user.email)
        }

        await transporter.sendMail(mailOptions)

        return res.json({ success: true, message: "OTP sent to email" });

    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
}

const resetPass = async (req, res) => {
    
    const {otp, email, newPassword} = req.body

    if(!email || !otp || !newPassword){
        return res.json({ success: false, message: "Missing credentials" });
    }

    try {
        const user = await userModel.findOne({email})

        if(!user){
            return res.json({ success: false, message: "User Not Found" });
        }
        
        if(user.resetOtp === '' || user.resetOtp !== otp){
            return res.json({ success: false, message: "Invalid Otp" });
        }

        if(user.resetOtpExpireAt < Date.now()){
            return res.json({ success: false, message: "OTP Expired" });
        }

        const hashedPass = await bcrypt.hash(newPassword, 10)

        user.password = hashedPass
        user.resetOtp = ''
        user.resetOtpExpireAt = 0
        await user.save()

        return res.json({ success: true, message: "Password Reset Succesfully" });

    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
}

export {login, register, logout, sendVerifyOtp, verifyEmail, isAuthenticated, sendResetOtp, resetPass}