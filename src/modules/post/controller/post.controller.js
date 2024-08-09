const Post = require("../model/post.model");
const User = require('../../user/model/user.model');


class PostController {
    async addPost(title, description, imageUrl, userId) {
        try {
            const newPost = new Post({
                title: title,
                description: description,
                image_url: imageUrl,
                created_at: new Date(),
                comments: [],
                likes: 0,
                status: 'In Progress',
                assigned_to: userId
            });

            const savedPost = await newPost.save();
            const user = await User.findById(userId);
    
            if (!user) {
                return { ok: false, message: 'User not found' };
            }
    
            user.postCount += 1;
            await user.save();
            return { ok: true, data: savedPost, message: "Post added successfully" };
        } catch (error) {
            console.error('Error adding post :::', error.message);
            return { ok: false, message: error.message };
        }
    }

    async posts() {
        try {
            const posts = await Post.find().populate('assigned_to', 'username'); // Optionally populate the assigned user
            return { ok: true, data: posts };
        } catch (error) {
            console.error("Error getting posts :::", error.message);
            return { ok: false, message: error.message };
        }
    }

    async post(id) {
        try {
            const post = await Post.findById(id).populate('assigned_to').populate('comments.user');
            if (!post) {
                return { ok: false, message: 'Post not found' };
            } else {
                return { ok: true, data: post };
            }
        } catch (error) {
            console.error('Error getting post:', error);
            return { ok: false, message: error.message };
        }
    }

    async getUserPosts(userId) {
        try {
            const posts = await Post.find({ 'assigned_to': userId }).populate('assigned_to', 'username');
            return { ok: true, data: posts };
        } catch (error) {
            console.error("Error getting assigned shipments :::", error.message);
            return { ok: false, message: error.message };
        }
    }

    async deletePost(postId, userId) {
        try {
            const post = await Post.findById(postId);
    
            if (!post) {
                return { ok: false, message: 'Post not found' };
            }
    
            if (post.assigned_to.toString() !== userId) {
                return { ok: false, message: 'User not authorized to delete this post' };
            }
    
            await Post.findByIdAndDelete(postId);
    
            const user = await User.findById(userId);
            if (user) {
                user.postCount -= 1;
                await user.save();
            }
    
            return { ok: true, message: 'Post deleted successfully' };
        } catch (error) {
            console.error('Error deleting post:', error);
            return { ok: false, message: error.message };
        }
    }
}

module.exports = new PostController();