const jwt = require('jsonwebtoken');

exports.authenticate = (req, res, next) => {
    const header = req.headers.authorization;
    if (!header) return res.status(403).json("Le token est absent.");

    const token = header.split(" ")[1];
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json("Le token est invalide.");
        req.user = user;
        next();
    });
};

exports.ensureAdmin = (req, res, next) => {
    if (req.user && req.user.roles.includes('ROLE_ADMIN')) {
        return next();
    }
    return res.status(403).json({ message: "Accès refusé : nécessite le rôle d'administrateur." });
};

exports.ensureSelfOrAdmin = (req, res, next) => {
    if (req.user && (req.user.id === req.params.uid || req.params.uid === 'me' || req.user.roles.includes('ROLE_ADMIN'))) {
        return next();
    }
    return res.status(403).json({ message: "Accès refusé : vous ne pouvez accéder qu'à votre propre compte, sauf si vous êtes administrateur." });
};
