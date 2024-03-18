const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const { generateToken, generateRefreshToken } = require('../utils/tokenUtils');
const { v4: uuidv4 } = require('uuid');

exports.register = async (req, res) => {
    try {
        const { login, email, password, roles, status } = req.body;

        // Check if user exists
        const userExists = await User.findOne({ $or: [{ login: login }, { email: email }] });
        if (userExists) {
            return res.status(422).json({error: { code: 422, message: "Cet utilisateur existe déjà."}});
        }

        // Create new user
        const newUser = new User({
            uid: uuidv4(),
            login,
            email,
            password,
            roles: roles || ['ROLE_USER'],
            status: status || 'open',
        });

        // Save user
        const savedUser = await newUser.save();

        res.status(201).json({
            uid: savedUser.uid,
            login: savedUser.login,
            email: savedUser.email,
            roles: savedUser.roles,
            status: savedUser.status,
            createdAt: savedUser.createdAt,
            updatedAt: savedUser.updatedAt
        });
    } catch (error) {
        res.status(500).json({error: { code: 500, message: error.message }});
    }
};

exports.login = async (req, res) => {
    try {
        const { login, password } = req.body;
        const user = await User.findOne({ login });
        if (!user) {
            res.status(404).json({error: { code: 404, message: "Ce compte n'existe pas." }});
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            res.status(401).json({error: { code: 401, message: "Le mot de passe est invalide." }});
        }

        const token = generateToken(user);
        const refreshToken = generateRefreshToken(user);

        res.status(201).json({ accessToken: token, accessTokenExpiresAt: new Date(Date.now() + 3600000), refreshToken, refreshTokenExpiresAt: new Date(Date.now() + 86400000) });
    } catch (error) {
        res.status(500).json({error: { code: 500, message: error.message }});
    }
};

exports.refreshToken = async (req, res) => {
    const { refreshToken } = req.params; // Récupérer le refresh token depuis les paramètres de la route
    if (!refreshToken) {
        return res.status(400).json({error: { code: 400, message: "Refresh token requis." }});
    }

    try {
        // Vérifier le refresh token
        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
        const user = await User.findById(decoded.id);
        if (!user) {
            return res.status(404).json({error: { code: 404, message: "Utilisateur non-trouvé." }});
        }

        // Générer un nouveau token d'accès et un nouveau refresh token
        const newAccessToken = generateToken(user);
        const newRefreshToken = generateRefreshToken(user);

        res.status(201).json({
            accessToken: newAccessToken,
            accessTokenExpiresAt: new Date(Date.now() + 60 * 60 * 1000), // Expiration dans 60 minutes
            refreshToken: newRefreshToken,
            refreshTokenExpiresAt: new Date(Date.now() + 120 * 60 * 1000) // Expiration dans 120 minutes
        });
    } catch (error) {
        if (error.name === 'JsonWebTokenError') {
            return res.status(403).json({error: { code: 403, message: "Token invalide ou inexistant." }});

        } else {
            return res.status(500).json({error: { code: 500, message: `Erreur interne (${error.message})` }});
        }
    }
};


exports.validateToken = async (req, res) => {
    const { token } = req.body;
    
    if (!token) {
        return res.status(400).json({error: { code: 400, message: "Access token requis." }});
    }

    try {
        jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
            if (err) return res.status(403).json({error: { code: 403, message: "Access token invalide." }});

            res.status(200).json({ 
                accessToken: token, 
                accessTokenExpiresAt: new Date(Date.now() + 3600000),
                user: user,
             });
        });
    } catch (error) {
        res.status(500).json({error: { code: 500, message: `Erreur interne (${error.message})` }});
    }
};

// Récupération d'un compte utilisateur
exports.getAccount = async (req, res) => {
    const { uid } = req.params;
    try {
        // Si "me" est utilisé, on récupère l'utilisateur actuel à partir du token JWT
        const userUid = uid === 'me' ? req.user.uid : uid;
        const user = await User.findOne({ uid: uid}).select('-_id'); // Exclure le champ _id du résultat

        if (!user) {
            return res.status(404).json({error: { code: 404, message: "Aucun utilisateur trouvé." }});
        }

        // Vérifier les rôles ici, si nécessaire.
        res.status(200).json({
            uid: user.uid,
            login: user.login,
            email: user.email,
            roles: user.roles,
            createdAt: user.createdAt,
            updatedAt: user.updatedAt
        });
    } catch (error) {
        res.status(500).json({error: { code: 500, message: error.message }});
    }
};

// Récupération de tous les comptes utilisateurs
exports.getAllAccounts = async (req, res) => {
    try {
        const users = await User.find();
        return res.status(200).json(users);
    } catch (error) {
        res.status(500).json({error: { code: 500, message: error.message }});
    }
};

// Modification d'un compte utilisateur
exports.updateUser = async (req, res) => {
    try {
        // Le mot-clé 'me' est remplacé par l'UID de l'utilisateur actuel, sinon on utilise l'UID fourni.
        const userUid = req.params.uid === 'me' ? req.user.uid : req.params.uid;
        const userToUpdate = await  User.findOne({ uid: userUid});

        if (!userToUpdate) {
            return res.status(404).json({error: { code: 404, message: "Aucun utilisateur trouvé." }});
        }

        // Vérifier si l'utilisateur courant est autorisé à mettre à jour l'utilisateur ciblé.
        const isSelfUpdate = req.user.uid === userToUpdate.uid;
        const isAdmin = req.user.roles.includes('ROLE_ADMIN');

        // Un utilisateur avec ROLE_USER peut modifier son propre compte, mais pas ses rôles.
        // Un administrateur peut modifier tous les comptes et les rôles.
        if (isSelfUpdate && !isAdmin) {
            delete req.body.roles; // Empêcher la modification des rôles par l'utilisateur lui-même.
        }

        // Appliquer les modifications autorisées
        const updates = req.body;
        if (updates.password) {
            updates.password = await bcrypt.hash(updates.password, 8); // Hasher le nouveau mot de passe
        }
        const updatedUser = await User.findOneAndUpdate({ uid: userUid }, updates, { new: true }).select('-_id');

        res.status(200).json({
            uid: updatedUser.uid,
            login: updatedUser.login,
            email: updatedUser.email,
            roles: updatedUser.roles,
            status: updatedUser.status,
            createdAt: updatedUser.createdAt,
            updatedAt: updatedUser.updatedAt
        });
    } catch (error) {
        res.status(500).json({error: { code: 500, message: error.message }});
    }
};



