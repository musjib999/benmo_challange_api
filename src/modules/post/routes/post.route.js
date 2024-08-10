const express = require("express");
const PostController = require("../controller/post.controller");

module.exports = (UPLOADS) => {
    const api = new express.Router();

    api.post("/", async (req, res) => {
        try {
            const { title, description, imageUrl, userId } = req.body;
            const { ok, data, message } = await PostController.addPost(title, description, imageUrl, userId);
            if (ok) {
                res.status(201).json({ ok, data });
            } else {
                res.status(500).json({ ok, message });
            }
        } catch (error) {
            res.status(500).json({ ok: false, message: error.message });
        }
    });

    api.get("/", async (req, res) => {
        try {
            const { ok, data, message } = await PostController.posts();
            if (ok) {
                res.status(200).json({ ok, data });
            } else {
                res.status(500).json({ ok, message });
            }
        } catch (error) {
            res.status(500).json({ ok: false, message: error.message });
        }
    });

    api.get("/:id", async (req, res) => {
        try {
            const postId = req.params.id;
            const { ok, data, message } = await PostController.post(postId);
            if (ok) {
                res.status(200).json({ ok, data });
            } else {
                res.status(500).json({ ok, message });
            }
        } catch (error) {
            res.status(500).json({ ok: false, message: error.message });
        }
    });

    // Route to get all posts by a specific user
    api.get("/user/:userId", async (req, res) => {
        try {
            const userId = req.params.userId;
            const { ok, data, message } = await PostController.getUserPosts(userId);
            if (ok) {
                res.status(200).json({ ok, data });
            } else {
                res.status(500).json({ ok, message });
            }
        } catch (error) {
            res.status(500).json({ ok: false, message: error.message });
        }
    });

    api.post("/:postId/comment", async (req, res) => {
        try {
            const { postId } = req.params;
            const { userId, commentText } = req.body;

            const { ok, data, message } = await PostController.addComment(postId, userId, commentText);
            if (ok) {
                res.status(201).json({ ok, data, message });
            } else {
                res.status(500).json({ ok, message });
            }
        } catch (error) {
            res.status(500).json({ ok: false, message: error.message });
        }
    });

    api.post("/:postId/:userId/like", async (req, res) => {
        try {
            const { postId, userId } = req.params;

            const { ok, message } = await PostController.likePost(postId, userId);
            if (ok) {
                res.status(201).json({ ok, message });
            } else {
                res.status(500).json({ ok, message });
            }
        } catch (error) {
            res.status(500).json({ ok: false, message: error.message });
        }
    });

    api.delete("/:postId", async (req, res) => {
        try {
            const postId = req.params.postId;

            const { userId } = req.body;
            const { ok, message } = await PostController.deletePost(postId, userId);
            if (ok) {
                res.status(200).json({ ok, data });
            } else {
                res.status(500).json({ ok, message });
            }
        } catch (error) {
            res.status(500).json({ ok: false, message: error.message });
        }
    });

    return api;
};
