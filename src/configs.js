const {
    APP_PORT,
    MONGO_URI,
    JWT_SECRET,
} = process.env

module.exports = {
    appPort: APP_PORT | 3000,
    mongoURI: MONGO_URI || "mongodb://localhost:27017/socialmedia",
    jwtSecret: JWT_SECRET || "e3d639f5a0a4c1f1c9cfa1d9b302bb7cc0308b24df2433091b9d506e9bb6369f",
}