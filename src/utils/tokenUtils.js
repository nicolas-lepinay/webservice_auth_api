const jwt = require('jsonwebtoken');

exports.generateToken = (user) => {
    return jwt.sign({ id: user._id, uid: user.uid, roles: user.roles, login: user.login, email: user.email }, process.env.JWT_SECRET, { expiresIn: '2h' });
};

exports.generateRefreshToken = (user) => {
    return jwt.sign({ id: user._id, uid: user.uid, roles: user.roles, login: user.login, email: user.email }, process.env.JWT_REFRESH_SECRET, { expiresIn: '2h' });
};
