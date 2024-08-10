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
                throw new Error("User not found");
            }else{
                user.posts += 1;
                await user.save();
                return { ok: true, data: savedPost, message: "Post added successfully" };
            }
        } catch (error) {
            console.error('Error adding post :::', error.message);
            return { ok: false, message: error.message };
        }
    }

    async posts() {
        try {
            const posts = await Post.find().populate('assigned_to', 'username profilePic');
            return { ok: true, data: posts };
        } catch (error) {
            console.error("Error getting posts :::", error.message);
            return { ok: false, message: error.message };
        }
    }

    async post(id) {
        try {
            const post = await Post.findById(id).populate('assigned_to').populate('comments.user', 'username profilePic');
            if (!post) {
                throw new Error('Post not found');
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
            const posts = await Post.find({ 'assigned_to': userId }).populate('assigned_to', 'username profilePic');
            return { ok: true, data: posts };
        } catch (error) {
            console.error("Error getting assigned shipments :::", error.message);
            return { ok: false, message: error.message };
        }
    }

    async addComment(postId, userId, commentText) {
        try {
            const post = await Post.findById(postId);
            if (!post) {
                throw new Error('Post not found');
            } else {
                const newComment = {
                    user: userId,
                    comment: commentText,
                    timestamp: new Date()
                };

                post.comments.push(newComment);

                const updatedPost = await post.save();

                return { ok: true, data: updatedPost, message: 'Comment added successfully' };
            }

        } catch (error) {
            console.error('Error adding comment:', error.message);
            return { ok: false, message: error.message };
        }
    }

    async likePost(postId, userId) {
        try {
            const post = await Post.findById(postId);
    
            if (!post) {
                throw new Error('Post not found');
            }
    
            if (!post.likedBy.includes(userId)) {
                post.likes += 1;
                post.likedBy.push(userId);
                await post.save();
                return { ok: true, message: 'Post liked successfully', data: post };
            } else {
                throw new Error('User has already liked this post');
            }
        } catch (error) {
            console.error('Error liking post:', error);
            return { ok: false, message: error.message };
        }
    }
    


    async deletePost(postId, userId) {
        try {
            const post = await Post.findById(postId);

            if (!post) {
                throw new Error('Post not found');
            }

            if (post.assigned_to.toString() !== userId) {
                throw new Error('User not authorized to delete this post');
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