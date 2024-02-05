const router = require('express').Router();
const { getAccount, register, login, updateUser, refreshToken, validateToken } = require('../controllers/authController');
const { authenticate, ensureSelfOrAdmin } = require('../middlewares/middleware');

// Récupération d'un compte utilisateur
router.get('/account/:uid', authenticate, ensureSelfOrAdmin, getAccount);

// Création d'un compte utilisateur
router.post('/account', register);

// Connexion
router.post('/token', login);

// Modification d'un compte utilisateur
router.put('/account/:uid', authenticate, ensureSelfOrAdmin, updateUser);

// Gestion des tokens de rafraîchissement
router.post('/refresh-token/:refreshToken/token', refreshToken);

// Validation du token
router.post('/validate', validateToken);

module.exports = router;
