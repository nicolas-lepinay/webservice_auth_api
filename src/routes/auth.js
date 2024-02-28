const router = require('express').Router();
const { getAccount, register, login, updateUser, refreshToken, validateToken } = require('../controllers/authController');
const { authenticate, ensureSelfOrAdmin } = require('../middlewares/middleware');

const ACCOUNT_ENDPOINT = process.env.ACCOUNT_ENDPOINT;
const LOGIN_ENDPOINT = process.env.LOGIN_ENDPOINT;
const VALIDATE_TOKEN_ENDPOINT = process.env.VALIDATE_TOKEN_ENDPOINT;
const REFRESH_TOKEN_ENDPOINT = process.env.REFRESH_TOKEN_ENDPOINT;

// Récupération d'un compte utilisateur
router.get(`${ACCOUNT_ENDPOINT}/:uid`, authenticate, ensureSelfOrAdmin, getAccount);

// Création d'un compte utilisateur
router.post(`${ACCOUNT_ENDPOINT}`, register);

// Connexion
router.post(`${LOGIN_ENDPOINT}`, login);

// Modification d'un compte utilisateur
router.put(`${ACCOUNT_ENDPOINT}/:uid`, authenticate, ensureSelfOrAdmin, updateUser);

// Gestion des tokens de rafraîchissement
router.post(`${REFRESH_TOKEN_ENDPOINT}/:refreshToken/token`, refreshToken);

// Validation du token
router.post(`${VALIDATE_TOKEN_ENDPOINT}`, validateToken);

module.exports = router;
