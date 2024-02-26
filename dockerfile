# Utiliser une image de node.js comme base
FROM node:21

# Définir le répertoire de travail dans le conteneur
WORKDIR /

# Copier le fichier package.json et package-lock.json
COPY package*.json ./

# Installer les dépendances
RUN npm install

# Copier le reste des fichiers de l'application
COPY . .

# Exposer le port sur lequel votre application Express écoute
EXPOSE 3000

# Commande pour exécuter votre application
CMD ["npm", "start"]
