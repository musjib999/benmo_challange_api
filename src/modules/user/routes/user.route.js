const express = require("express");
const AuthController = require("../controller/user.controller");

module.exports = () => {
    const api = new express.Router();

    api.post("/register", async (req, res) => {
        try {
            const body = req.body;
            const { ok, data, message } = await AuthController.register(body);
            if (ok) {
                res.status(201).json({ ok, data, message });
            } else {
                res.status(500).json({ ok, message });
            }
            
        } catch (error) {
            for (const iterator of req.uploadedFiles) {
                rollbackUpload(iterator.fileKey)
            }
            res.status(500).json({ ok: false, message: error.message });
        }
    });

    api.post("/login", async (req, res) => {
        try {
          const { email, password } = req.body;
          const { ok, data, message } = await AuthController.login(email, password);
          if (ok) {
            res.status(200).json({ ok, data });
          } else {
            res.status(500).json({ ok, message });
          }
        } catch (error) {
          res.status(500).json({ ok: false, message: error.message });
        }
      });

      api.post("/:userId/:followeeId/follow", async (req, res) => {
        try {
          const { userId, followeeId } = req.params;
          const { ok, message } = await AuthController.followUser(userId, followeeId);
          if (ok) {
            res.status(200).json({ ok, message });
          } else {
            res.status(500).json({ ok, message });
          }
        } catch (error) {
          res.status(500).json({ ok: false, message: error.message });
        }
      });

      api.post("/:userId/:followeeId/unfollow", async (req, res) => {
        try {
          const { userId, followeeId } = req.params;
          const { ok, message } = await AuthController.unfollowUser(userId, followeeId);
          if (ok) {
            res.status(200).json({ ok, message });
          } else {
            res.status(500).json({ ok, message });
          }
        } catch (error) {
          res.status(500).json({ ok: false, message: error.message });
        }
      });

      return api;
}