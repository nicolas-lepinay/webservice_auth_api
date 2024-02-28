const jwt = require('jsonwebtoken');

exports.generateToken = (user) => {
    return jwt.sign({ id: user._id, roles: user.roles }, process.env.JWT_SECRET, { expiresIn: '1h' });
};

exports.generateRefreshToken = (user) => {
    return jwt.sign({ id: user._id, roles: user.roles }, process.env.JWT_REFRESH_SECRET, { expiresIn: '2h' });
};
