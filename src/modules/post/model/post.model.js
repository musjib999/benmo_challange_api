const mongoose = require('mongoose');
const { Schema } = mongoose;

const CommentSchema = new mongoose.Schema({
    user: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    comment: { type: String, required: true },
    timestamp: { type: Date, default: Date.now }
});

const PostSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String, required: true },
    image_url: { type: String },
    created_at: { type: Date, default: Date.now },
    comments: [CommentSchema],
    likes: { type: Number, image_urldefault: 0 },
    likedBy: [{ type: Schema.Types.ObjectId, ref: 'User' }],
    status: {
        type: String,
        enum: ['In Progress', 'Completed', 'Overdue'],
        default: 'In Progress'
    },
    assigned_to: { type: Schema.Types.ObjectId, ref: 'User', required: true }
});

module.exports = mongoose.model('Post', PostSchema);
