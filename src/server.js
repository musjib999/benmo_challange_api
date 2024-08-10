const UPLOADS = __dirname + "/uploads"
require("./connections/mongo.connection")();
// const { verifyToken } = require("./middleware/auth.middleware")
const { appPort } = require("./configs");
const express = require("express");
const cors = require("cors");
const app = express();

app.use(cors());
app.use(express.json({ limit: "200mb" }));
app.use(express.urlencoded({ extended: true }));

app.use("/api/v1/post", require("./modules/post/routes/post.route")(UPLOADS));
app.use("/api/v1/user", require("./modules/user/routes/user.route")());
app.use("/uploads", express.static(UPLOADS));

// app.use(verifyToken);



app.listen(appPort, () => {
    console.log("Social media service listening on port: " + appPort);
});