const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

const UserSchema = new mongoose.Schema(
    {
        email: {
            index: { unique: true },
            type: String,
            required: [true, "Email is required"],
            lowercase: true,
            validate: [
                (email) => /^([\w-.]+@([\w-]+\.)+[\w-]{2,4})?$/.test(email),
                "Please fill a valid email address",
            ],
        },
        password: {
            type: String,
            required: true
        },
        username: {
            type: String,
            required: true
        },
        followers: {
            type: Number,
            default: 0
        },
        profilePic: {
            type: String,
        },
        posts: {
            type: Number,
            default: 0
        }
    },
    { timestamps: true }
);

UserSchema.pre("save", function (next, opt) {
    let { skipHashing } = opt;
    if (!skipHashing) {
        bcrypt.hash(this.password, 10, async (err, hash) => {
            if (err) return next(err);
            this.password = hash;
            this.fullName = `${this.firstName} ${this.lastName}`;
            next();
        });
    } else {
        console.log("Skipping Password Hash !!!");
        next()
    }
});

UserSchema.methods.isValidPassword = function (password) {
    if (!this.password) {
        throw new Error("Password is not set for this user");
    }
    return bcrypt.compare(password, this.password);
};


module.exports = mongoose.model("User", UserSchema);