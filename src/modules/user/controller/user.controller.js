const AuthModel = require('../model/user.model');
const jwt = require("jsonwebtoken");
const { jwtSecret } = require("../../../configs");

class AuthController {
    async register(body) {
        try {
            const newUser = new AuthModel(body);
            await newUser.save();
            newUser.password = "********";

            return {
                ok: true,
                data: newUser,
                message: "Registration successful",
            };
        } catch (error) {
            return this.handleDuplicateKeyError(error);
        }
    }

    async login(email, password) {
        try {
            const user = await AuthModel.findOne({ email });
            if (!user) {
                throw new Error("User not found");
            }

            const isValid = await user.isValidPassword(password);
            console.log(isValid);
            if (!isValid) {
                throw new Error("Invalid password");
            }

            const accessToken = this.encodeToken(
                { email: user.email, id: user._id },
                { expiresIn: "1h" }
            );
            const refreshToken = this.encodeToken(
                { email: user.email, role: user.role, id: user._id }
            );
            //await redisCtrl.write(`token::${user.email}`, refreshToken)

            return { ok: true, data: { user, accessToken, refreshToken }, message: "Login successful" };
        } catch (error) {
            return { ok: false, message: error.message };
        }
    }

    async followUser(followerId, followeeId) {
        try {
            const followee = await AuthModel.findById(followeeId);
    
            if (!followee) {
                console.log('User to follow not found');
                return { success: false, message: 'User not found' };
            }
    
            if (!followee.followers.includes(followerId)) {
                followee.followers.push(followerId);
                await followee.save();
                console.log(`${followerId} is now following ${followeeId}`);
                return { ok: true, message: 'User followed successfully' };
            } else {
                return { ok: false, message: 'Already following this user' };
            }
        } catch (error) {
            console.error('Error following user:', error);
            return { ok: false, message: error.message };
        }
    }


    encodeToken(payload, options = {}) {
        return jwt.sign(payload, jwtSecret, options);
    }

    decodeToken(token) {
        try {
            return jwt.verify(token, jwtSecret);
        } catch (error) {
            console.log("Token not verified:", error.message);
            return null;
        }
    }

    handleDuplicateKeyError(error) {
        if (error.code === 11000) {
            const matches = error.message.match(/index: (.+?) dup key: { (.+?) }/);
            if (matches) {
                const [, fieldName, fieldValue] = matches;
                return { ok: false, message: `A user with the '${fieldValue}' already exists.` };
            } else {
                return { ok: false, message: "A duplicate value was provided. Please check your information." };
            }
        } else {
            console.log("Error creating user:", error.message);
            return { ok: false, message: error.message };
        }
    }
}

module.exports = new AuthController();