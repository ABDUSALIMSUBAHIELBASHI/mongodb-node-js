const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

dotenv.config();

const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/contactDB';
const JWT_SECRET = process.env.JWT_SECRET || 'your_secret_key_here';

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// MongoDB Connection
mongoose.connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('✅ Successfully connected to MongoDB'))
.catch(err => console.error('❌ MongoDB connection error:', err));

// ============= USER SCHEMA (Full Registration) =============
const userSchema = new mongoose.Schema({
    fullName: {
        type: String,
        required: [true, 'Full name is required'],
        trim: true,
        minlength: [2, 'Name must be at least 2 characters'],
        maxlength: [50, 'Name cannot exceed 50 characters']
    },
    email: {
        type: String,
        required: [true, 'Email is required'],
        unique: true,
        lowercase: true,
        trim: true,
        match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
    },
    password: {
        type: String,
        required: [true, 'Password is required'],
        minlength: [6, 'Password must be at least 6 characters'],
        select: false
    },
    phone: {
        type: String,
        trim: true,
        default: ''
    },
    age: {
        type: Number,
        min: [1, 'Age must be at least 1'],
        max: [120, 'Age cannot exceed 120']
    },
    gender: {
        type: String,
        enum: ['male', 'female', 'other', 'prefer-not-to-say'],
        default: 'prefer-not-to-say'
    },
    address: {
        street: { type: String, default: '' },
        city: { type: String, default: '' },
        state: { type: String, default: '' },
        zipCode: { type: String, default: '' },
        country: { type: String, default: '' }
    },
    role: {
        type: String,
        enum: ['user', 'admin', 'moderator'],
        default: 'user'
    },
    isActive: {
        type: Boolean,
        default: true
    },
    isVerified: {
        type: Boolean,
        default: false
    },
    lastLogin: {
        type: Date,
        default: null
    },
    profilePicture: {
        type: String,
        default: null
    },
    bio: {
        type: String,
        maxlength: [500, 'Bio cannot exceed 500 characters'],
        default: ''
    },
    interests: [{
        type: String
    }],
    registrationDate: {
        type: Date,
        default: Date.now
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
}, {
    timestamps: true
});

// Hash password before saving
userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    
    try {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error) {
        next(error);
    }
});

// Compare password method
userSchema.methods.comparePassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

// Generate JWT Token
userSchema.methods.generateAuthToken = function() {
    return jwt.sign(
        { 
            id: this._id, 
            email: this.email, 
            role: this.role 
        }, 
        JWT_SECRET, 
        { expiresIn: '7d' }
    );
};

const User = mongoose.model('User', userSchema);

// ============= CONTACT MESSAGE SCHEMA =============
const contactSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'Name is required'],
        trim: true
    },
    email: {
        type: String,
        required: [true, 'Email is required'],
        trim: true,
        lowercase: true
    },
    message: {
        type: String,
        required: [true, 'Message is required'],
        trim: true,
        minlength: [5, 'Message must be at least 5 characters'],
        maxlength: [1000, 'Message cannot exceed 1000 characters']
    },
    subject: {
        type: String,
        trim: true,
        default: 'General Inquiry'
    },
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        default: null
    },
    status: {
        type: String,
        enum: ['unread', 'read', 'replied', 'archived', 'spam'],
        default: 'unread'
    },
    priority: {
        type: String,
        enum: ['low', 'medium', 'high', 'urgent'],
        default: 'medium'
    },
    date: {
        type: String,
        default: () => new Date().toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'long',
            day: 'numeric'
        })
    },
    time: {
        type: String,
        default: () => new Date().toLocaleTimeString('en-US', {
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        })
    },
    ipAddress: String,
    userAgent: String,
    attachments: [{
        filename: String,
        url: String,
        size: Number
    }],
    reply: {
        message: String,
        repliedBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User'
        },
        repliedAt: Date
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
}, {
    timestamps: true
});

const Contact = mongoose.model('Contact', contactSchema);

// ============= AUTHENTICATION MIDDLEWARE =============
const authMiddleware = async (req, res, next) => {
    try {
        const token = req.header('Authorization')?.replace('Bearer ', '');
        
        if (!token) {
            throw new Error();
        }

        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.id).select('-password');
        
        if (!user) {
            throw new Error();
        }

        req.user = user;
        req.token = token;
        next();
    } catch (error) {
        res.status(401).json({
            success: false,
            error: 'Please authenticate'
        });
    }
};

const adminMiddleware = async (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({
            success: false,
            error: 'Access denied. Admin only.'
        });
    }
    next();
};

// ============= API ROUTES =============

// ===== USER REGISTRATION ROUTES (FULL ACTION) =====

// Register new user with full details
app.post('/api/register', async (req, res) => {
    try {
        const { 
            fullName, 
            email, 
            password, 
            phone, 
            age, 
            gender, 
            address, 
            bio, 
            interests 
        } = req.body;

        // Check if user already exists
        const existingUser = await User.findOne({ email: email.toLowerCase() });
        if (existingUser) {
            return res.status(400).json({
                success: false,
                error: 'Email already registered'
            });
        }

        // Create new user with all fields
        const user = new User({
            fullName,
            email: email.toLowerCase(),
            password,
            phone: phone || '',
            age: age || null,
            gender: gender || 'prefer-not-to-say',
            address: address || {},
            bio: bio || '',
            interests: interests || [],
            registrationDate: new Date()
        });

        await user.save();

        // Generate token
        const token = user.generateAuthToken();

        // Remove password from response
        user.password = undefined;

        res.status(201).json({
            success: true,
            message: 'User registered successfully',
            token,
            data: user
        });
    } catch (error) {
        console.error('Registration error:', error);
        
        if (error.name === 'ValidationError') {
            return res.status(400).json({
                success: false,
                error: Object.values(error.errors).map(e => e.message).join(', ')
            });
        }

        res.status(500).json({
            success: false,
            error: 'Registration failed. Please try again.'
        });
    }
});

// Login user
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ email: email.toLowerCase() }).select('+password');
        
        if (!user) {
            return res.status(401).json({
                success: false,
                error: 'Invalid email or password'
            });
        }

        const isPasswordValid = await user.comparePassword(password);
        
        if (!isPasswordValid) {
            return res.status(401).json({
                success: false,
                error: 'Invalid email or password'
            });
        }

        // Update last login
        user.lastLogin = new Date();
        await user.save();

        // Generate token
        const token = user.generateAuthToken();

        // Remove password from response
        user.password = undefined;

        res.status(200).json({
            success: true,
            message: 'Login successful',
            token,
            data: user
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            error: 'Login failed. Please try again.'
        });
    }
});

// Get current user profile
app.get('/api/profile', authMiddleware, async (req, res) => {
    try {
        res.status(200).json({
            success: true,
            data: req.user
        });
    } catch (error) {
        console.error('Error fetching profile:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch profile'
        });
    }
});

// Update user profile
app.put('/api/profile', authMiddleware, async (req, res) => {
    try {
        const { fullName, phone, age, gender, address, bio, interests } = req.body;
        
        const user = await User.findByIdAndUpdate(
            req.user._id,
            {
                fullName,
                phone,
                age,
                gender,
                address,
                bio,
                interests,
                updatedAt: Date.now()
            },
            { new: true, runValidators: true }
        ).select('-password');

        res.status(200).json({
            success: true,
            message: 'Profile updated successfully',
            data: user
        });
    } catch (error) {
        console.error('Error updating profile:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to update profile'
        });
    }
});

// ===== ADMIN ROUTES - SEE ALL REGISTRATIONS =====

// Get all users with full details (Admin only)
app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { page = 1, limit = 20, search, role, status } = req.query;
        
        // Build filter
        let filter = {};
        if (search) {
            filter.$or = [
                { fullName: { $regex: search, $options: 'i' } },
                { email: { $regex: search, $options: 'i' } },
                { phone: { $regex: search, $options: 'i' } }
            ];
        }
        if (role) filter.role = role;
        if (status) filter.isActive = status === 'active';

        const users = await User.find(filter)
            .select('-password')
            .sort({ createdAt: -1 })
            .limit(limit * 1)
            .skip((page - 1) * limit);

        const total = await User.countDocuments(filter);

        res.status(200).json({
            success: true,
            total,
            page: parseInt(page),
            limit: parseInt(limit),
            pages: Math.ceil(total / limit),
            data: users
        });
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch users'
        });
    }
});

// Get single user by ID with their messages (Admin only)
app.get('/api/admin/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.params.id).select('-password');
        
        if (!user) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }

        // Get user's messages
        const messages = await Contact.find({ userId: req.params.id })
            .sort({ createdAt: -1 });

        res.status(200).json({
            success: true,
            data: {
                user,
                messages,
                totalMessages: messages.length
            }
        });
    } catch (error) {
        console.error('Error fetching user:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch user'
        });
    }
});

// Delete user (Admin only)
app.delete('/api/admin/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const user = await User.findByIdAndDelete(req.params.id);
        
        if (!user) {
            return res.status(404).json({
                success: false,
                error: 'User not found'
            });
        }

        // Also delete all messages from this user
        await Contact.deleteMany({ userId: req.params.id });

        res.status(200).json({
            success: true,
            message: 'User and associated messages deleted successfully'
        });
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to delete user'
        });
    }
});

// ===== CONTACT MESSAGE ROUTES =====

// Get all messages (Admin only)
app.get('/api/admin/messages', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { page = 1, limit = 20, status, priority, search } = req.query;
        
        // Build filter
        let filter = {};
        if (status) filter.status = status;
        if (priority) filter.priority = priority;
        if (search) {
            filter.$or = [
                { name: { $regex: search, $options: 'i' } },
                { email: { $regex: search, $options: 'i' } },
                { message: { $regex: search, $options: 'i' } }
            ];
        }

        const messages = await Contact.find(filter)
            .sort({ createdAt: -1 })
            .populate('userId', 'fullName email phone')
            .limit(limit * 1)
            .skip((page - 1) * limit);

        const total = await Contact.countDocuments(filter);

        res.status(200).json({
            success: true,
            total,
            page: parseInt(page),
            limit: parseInt(limit),
            pages: Math.ceil(total / limit),
            data: messages
        });
    } catch (error) {
        console.error('Error fetching messages:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch messages'
        });
    }
});

// Get messages by user ID
app.get('/api/messages/user/:userId', authMiddleware, async (req, res) => {
    try {
        // Users can only see their own messages unless admin
        if (req.user.role !== 'admin' && req.user._id.toString() !== req.params.userId) {
            return res.status(403).json({
                success: false,
                error: 'Access denied'
            });
        }

        const messages = await Contact.find({ userId: req.params.userId })
            .sort({ createdAt: -1 });
        
        res.status(200).json({
            success: true,
            count: messages.length,
            data: messages
        });
    } catch (error) {
        console.error('Error fetching user messages:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch user messages'
        });
    }
});

// Create new message (Public)
app.post('/api/messages', async (req, res) => {
    try {
        const { name, email, message, subject, priority, userId } = req.body;

        if (!name || !email || !message) {
            return res.status(400).json({
                success: false,
                error: 'Please provide name, email, and message'
            });
        }

        const newMessage = new Contact({
            name: name.trim(),
            email: email.trim().toLowerCase(),
            message: message.trim(),
            subject: subject || 'General Inquiry',
            priority: priority || 'medium',
            userId: userId || null,
            ipAddress: req.ip,
            userAgent: req.get('user-agent')
        });

        await newMessage.save();

        res.status(201).json({
            success: true,
            message: 'Message sent successfully!',
            data: newMessage
        });
    } catch (error) {
        console.error('Error saving message:', error);
        
        if (error.name === 'ValidationError') {
            return res.status(400).json({
                success: false,
                error: Object.values(error.errors).map(e => e.message).join(', ')
            });
        }

        res.status(500).json({
            success: false,
            error: 'Failed to send message. Please try again.'
        });
    }
});

// Update message status (Admin only)
app.patch('/api/admin/messages/:id/status', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { status } = req.body;
        
        const message = await Contact.findByIdAndUpdate(
            req.params.id,
            { status },
            { new: true }
        );

        if (!message) {
            return res.status(404).json({
                success: false,
                error: 'Message not found'
            });
        }

        res.status(200).json({
            success: true,
            message: 'Message status updated',
            data: message
        });
    } catch (error) {
        console.error('Error updating message status:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to update message status'
        });
    }
});

// Reply to message (Admin only)
app.post('/api/admin/messages/:id/reply', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const { replyMessage } = req.body;
        
        const message = await Contact.findByIdAndUpdate(
            req.params.id,
            {
                status: 'replied',
                reply: {
                    message: replyMessage,
                    repliedBy: req.user._id,
                    repliedAt: new Date()
                }
            },
            { new: true }
        );

        if (!message) {
            return res.status(404).json({
                success: false,
                error: 'Message not found'
            });
        }

        res.status(200).json({
            success: true,
            message: 'Reply sent successfully',
            data: message
        });
    } catch (error) {
        console.error('Error replying to message:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to send reply'
        });
    }
});

// Delete message (Admin only)
app.delete('/api/admin/messages/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const message = await Contact.findByIdAndDelete(req.params.id);
        
        if (!message) {
            return res.status(404).json({
                success: false,
                error: 'Message not found'
            });
        }

        res.status(200).json({
            success: true,
            message: 'Message deleted successfully',
            data: message
        });
    } catch (error) {
        console.error('Error deleting message:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to delete message'
        });
    }
});

// ===== STATISTICS ROUTES =====

// Get dashboard statistics (Admin only)
app.get('/api/admin/stats', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        const activeUsers = await User.countDocuments({ isActive: true });
        const verifiedUsers = await User.countDocuments({ isVerified: true });
        const newUsersToday = await User.countDocuments({
            createdAt: { $gte: new Date().setHours(0,0,0,0) }
        });
        
        const totalMessages = await Contact.countDocuments();
        const unreadMessages = await Contact.countDocuments({ status: 'unread' });
        const urgentMessages = await Contact.countDocuments({ priority: 'urgent', status: 'unread' });
        
        // Users by role
        const usersByRole = await User.aggregate([
            { $group: { _id: "$role", count: { $sum: 1 } } }
        ]);

        // Messages by status
        const messagesByStatus = await Contact.aggregate([
            { $group: { _id: "$status", count: { $sum: 1 } } }
        ]);

        // Messages per day (last 30 days)
        const thirtyDaysAgo = new Date();
        thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
        
        const messagesPerDay = await Contact.aggregate([
            {
                $match: {
                    createdAt: { $gte: thirtyDaysAgo }
                }
            },
            {
                $group: {
                    _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
                    count: { $sum: 1 }
                }
            },
            { $sort: { _id: 1 } }
        ]);

        // Recent registrations
        const recentRegistrations = await User.find()
            .select('fullName email createdAt')
            .sort({ createdAt: -1 })
            .limit(10);

        res.status(200).json({
            success: true,
            data: {
                users: {
                    total: totalUsers,
                    active: activeUsers,
                    verified: verifiedUsers,
                    newToday: newUsersToday,
                    byRole: usersByRole,
                    recent: recentRegistrations
                },
                messages: {
                    total: totalMessages,
                    unread: unreadMessages,
                    urgent: urgentMessages,
                    byStatus: messagesByStatus,
                    perDay: messagesPerDay
                }
            }
        });
    } catch (error) {
        console.error('Error fetching stats:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch statistics'
        });
    }
});

// ===== PUBLIC ROUTES =====

// Health check
app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        mongodb: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected',
        environment: process.env.NODE_ENV || 'development'
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`\n🚀 Server running on http://localhost:${PORT}`);
    console.log(`📊 API Endpoints:`);
    console.log(`\n👤 Public Routes:`);
    console.log(`   POST   http://localhost:${PORT}/api/register     - Register new user (Full details)`);
    console.log(`   POST   http://localhost:${PORT}/api/login        - Login user`);
    console.log(`   POST   http://localhost:${PORT}/api/messages     - Send message`);
    console.log(`   GET    http://localhost:${PORT}/health          - Health check`);
    
    console.log(`\n👤 User Routes (Auth Required):`);
    console.log(`   GET    http://localhost:${PORT}/api/profile     - Get profile`);
    console.log(`   PUT    http://localhost:${PORT}/api/profile     - Update profile`);
    console.log(`   GET    http://localhost:${PORT}/api/messages/user/:userId - Get user messages`);
    
    console.log(`\n👑 Admin Routes (Admin Only):`);
    console.log(`   GET    http://localhost:${PORT}/api/admin/users        - Get all users with pagination`);
    console.log(`   GET    http://localhost:${PORT}/api/admin/users/:id    - Get user with messages`);
    console.log(`   DELETE http://localhost:${PORT}/api/admin/users/:id    - Delete user`);
    console.log(`   GET    http://localhost:${PORT}/api/admin/messages     - Get all messages`);
    console.log(`   PATCH  http://localhost:${PORT}/api/admin/messages/:id/status - Update message status`);
    console.log(`   POST   http://localhost:${PORT}/api/admin/messages/:id/reply - Reply to message`);
    console.log(`   DELETE http://localhost:${PORT}/api/admin/messages/:id - Delete message`);
    console.log(`   GET    http://localhost:${PORT}/api/admin/stats        - Get dashboard stats\n`);
});