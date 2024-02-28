# Utiliser une image de node.js comme base
FROM node:20-slim

# Définir le répertoire de travail dans le conteneur
WORKDIR /app

# Copier les fichiers package.json et package-lock.json
COPY src/package*.json ./

# Installer les dépendances
RUN npm install --production

# Copier le reste des fichiers de l'application
COPY src/ .

# Exposer le port sur lequel votre application Express écoute
EXPOSE 3001

# Commande pour exécuter votre application
CMD ["node", "index.js"]