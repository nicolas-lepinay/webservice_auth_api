const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const UserSchema = new mongoose.Schema({
    login: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    roles: [{ type: String, enum: ['ROLE_USER', 'ROLE_ADMIN'], default: 'ROLE_USER' }],
    status: { type: String, enum: ['open', 'closed'], default: 'open' }
}, { timestamps: true });

// Middleware to hash password before saving user
UserSchema.pre('save', async function (next) {
    if (this.isModified('password')) {
        this.password = await bcrypt.hash(this.password, 8);
    }
    next();
});

module.exports = mongoose.model("User", UserSchema);
