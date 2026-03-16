require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const { GoogleGenerativeAI } = require('@google/generative-ai');

const app = express();
const PORT = process.env.PORT || 8080;
const GEMINI_MODEL_NAME = 'gemini-2.5-flash';
const geminiApiKey = process.env.GEMINI_API_KEY;
const geminiClient = geminiApiKey ? new GoogleGenerativeAI(geminiApiKey) : null;
const geminiModel = geminiClient ? geminiClient.getGenerativeModel({ model: GEMINI_MODEL_NAME }) : null;
const escapeRegex = (value = '') => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// Create uploads directory if it doesn't exist
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

// Multer config for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname);
        cb(null, uniqueName);
    }
});

const upload = multer({
    storage: storage,
    fileFilter: (req, file, cb) => {
        const allowedMimes = [
            'image/jpeg', 'image/png', 'image/gif', 'image/webp',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        ];
        if (allowedMimes.includes(file.mimetype) || file.originalname.endsWith('.docx')) {
            cb(null, true);
        } else {
            cb(new Error('Only image and Word files are allowed'));
        }
    }
});

// Middleware
app.use(cors());
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static(path.join(__dirname, '.')));
app.use('/uploads', express.static(uploadDir));

// MongoDB Connection
mongoose.connect(process.env.MONGO_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('✅ MongoDB Connected'))
.catch(err => console.error('❌ MongoDB Connection Error:', err));

// ============================================
// SCHEMAS
// ============================================

// User Schema
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    email: { type: String, unique: true, sparse: true },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

// Updated ChatData Schema - with userId tracking
const ChatDataSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    uploadedBy: { type: String, required: true },
    title: { type: String, required: true },
    content: { type: String, required: true },
    fileType: { type: String, enum: ['text', 'word'], default: 'text' },
    htmlContent: { type: String, default: null },
    imageCount: { type: Number, default: 0 },
    date: { type: String, default: () => new Date().toLocaleString('vi-VN') },
    uploadDate: { type: Date, default: Date.now },
    createdAt: { type: Date, default: Date.now }
});

// Carousel Images Schema
const CarouselImageSchema = new mongoose.Schema({
    title: { type: String, required: true },
    imageUrl: { type: String, required: true },
    alt: { type: String, default: '' },
    order: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const ChatData = mongoose.model('ChatData', ChatDataSchema);
const CarouselImage = mongoose.model('CarouselImage', CarouselImageSchema);

// ============================================
// SESSION STORAGE (simple in-memory)
// ============================================
const sessions = new Map(); // {sessionId: {userId, username, role, expiresAt}}

const createSession = (userId, username, role) => {
    const sessionId = Math.random().toString(36).substring(2, 15);
    const expiresAt = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
    sessions.set(sessionId, { userId, username, role, expiresAt });
    return sessionId;
};

const getSession = (sessionId) => {
    const session = sessions.get(sessionId);
    if (session && session.expiresAt > Date.now()) {
        return session;
    }
    sessions.delete(sessionId);
    return null;
};

const deleteSession = (sessionId) => {
    sessions.delete(sessionId);
};

// Middleware: Check authentication
const requireAuth = (req, res, next) => {
    const sessionId = req.headers['x-session-id'] || req.body.sessionId;
    const session = getSession(sessionId);
    if (!session) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    req.user = session;
    req.sessionId = sessionId;
    next();
};

const requireAdmin = (req, res, next) => {
    const sessionId = req.headers['x-session-id'] || req.body.sessionId;
    const session = getSession(sessionId);
    if (!session || session.role !== 'admin') {
        return res.status(403).json({ error: 'Forbidden: Admin access required' });
    }
    req.user = session;
    req.sessionId = sessionId;
    next();
};

// ============================================
// AUTHENTICATION ROUTES
// ============================================

// Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        const user = await User.findOne({ username });
        if (!user) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        // Plain text comparison (as per user requirement)
        if (user.password !== password) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        const sessionId = createSession(user._id, user.username, user.role);
        res.json({
            success: true,
            sessionId,
            username: user.username,
            role: user.role
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Logout
app.post('/api/auth/logout', (req, res) => {
    const sessionId = req.headers['x-session-id'];
    if (sessionId) {
        deleteSession(sessionId);
    }
    res.json({ success: true, message: 'Logged out' });
});

// Check session
app.get('/api/auth/check', (req, res) => {
    const sessionId = req.headers['x-session-id'];
    const session = getSession(sessionId);

    if (session) {
        res.json({
            authenticated: true,
            username: session.username,
            role: session.role,
            userId: session.userId
        });
    } else {
        res.json({ authenticated: false });
    }
});

// ============================================
// USER MANAGEMENT ROUTES (Admin only)
// ============================================

// Get all users
app.get('/api/users', requireAdmin, async (req, res) => {
    try {
        const users = await User.find().select('-password').sort({ createdAt: -1 });
        const usersWithStats = await Promise.all(users.map(async (user) => {
            const dataCount = await ChatData.countDocuments({ userId: user._id });
            return {
                id: user._id,
                username: user.username,
                email: user.email,
                role: user.role,
                createdAt: user.createdAt,
                dataCount
            };
        }));
        res.json(usersWithStats);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Create new user (Admin only)
app.post('/api/users', requireAdmin, async (req, res) => {
    try {
        const { username, password, email, role } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ error: 'Username already exists' });
        }

        const newUser = new User({
            username,
            password,
            email: email || undefined,
            role: role || 'user'
        });

        await newUser.save();
        console.log(`✅ Created new user: ${username} (${role || 'user'})`);

        res.json({
            success: true,
            id: newUser._id,
            username: newUser.username,
            email: newUser.email,
            role: newUser.role,
            createdAt: newUser.createdAt
        });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// Delete user (Admin only)
app.delete('/api/users/:id', requireAdmin, async (req, res) => {
    try {
        const user = await User.findByIdAndDelete(req.params.id);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Delete all data uploaded by this user
        const deleteResult = await ChatData.deleteMany({ userId: user._id });
        console.log(`🗑️ Deleted user: ${user.username} and ${deleteResult.deletedCount} related data items`);

        res.json({
            success: true,
            message: `User deleted and ${deleteResult.deletedCount} data items removed`
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============================================
// DATA ROUTES - UPDATED for User Tracking
// ============================================

// Get all data (public endpoint)
app.get('/api/data', async (req, res) => {
    try {
        const data = await ChatData.find().sort({ createdAt: -1 });
        const formattedData = data.map(item => ({
            id: item._id,
            title: item.title,
            content: item.content,
            fileType: item.fileType || 'text',
            htmlContent: item.htmlContent,
            imageCount: item.imageCount || 0,
            date: item.date,
            uploadedBy: item.uploadedBy,
            uploadDate: item.uploadDate
        }));
        res.json(formattedData);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Add new data (public endpoint)
app.post('/api/data', async (req, res) => {
    try {
        const { title, content, fileType, htmlContent, imageCount, uploadedBy } = req.body;

        if (!title || !content) {
            return res.status(400).json({ error: 'Title and content are required' });
        }

        // Use a default user ID for public submissions
        const defaultUserId = new mongoose.Types.ObjectId();

        const newData = new ChatData({
            userId: defaultUserId,
            uploadedBy: uploadedBy || 'Anonymous',
            title,
            content,
            fileType: fileType || 'text',
            htmlContent: htmlContent || null,
            imageCount: imageCount || 0
        });

        await newData.save();

        console.log(`✅ Saved new ${fileType || 'text'} data by ${uploadedBy || 'Anonymous'}: "${title}"${imageCount > 0 ? ` with ${imageCount} images` : ''}`);

        res.json({
            id: newData._id,
            title: newData.title,
            content: newData.content,
            fileType: newData.fileType,
            htmlContent: newData.htmlContent,
            imageCount: newData.imageCount,
            date: newData.date,
            uploadedBy: newData.uploadedBy,
            uploadDate: newData.uploadDate
        });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// Delete data (public endpoint)
app.delete('/api/data/:id', async (req, res) => {
    try {
        const data = await ChatData.findById(req.params.id);
        if (!data) {
            return res.status(404).json({ error: 'Data not found' });
        }

        await ChatData.findByIdAndDelete(req.params.id);
        console.log(`🗑️ Deleted data: "${data.title}"`);
        res.json({ message: 'Deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// UPDATED Ask endpoint - support Word documents in context
app.post('/api/ask', requireAuth, async (req, res) => {
    try {
        if (!geminiModel) {
            return res.status(500).json({ error: 'Thiếu cấu hình Gemini API' });
        }

        const question = (req.body.question || '').trim();
        if (!question) {
            return res.status(400).json({ error: 'Vui lòng nhập câu hỏi' });
        }

        const regex = new RegExp(escapeRegex(question), 'i');
        let relevantData = await ChatData.find({
            userId: req.user.userId,
            $or: [
                { title: { $regex: regex } },
                { content: { $regex: regex } }
            ]
        }).limit(6);

        if (relevantData.length === 0) {
            relevantData = await ChatData.find({ userId: req.user.userId }).sort({ createdAt: -1 }).limit(6);
        }

        const context = relevantData.map((item, index) => {
            let itemText = `Mục ${index + 1}: ${item.title}\nNgày lưu: ${item.date}\nNội dung: ${item.content}`;
            if (item.fileType === 'word' && item.imageCount > 0) {
                itemText += `\n(Tài liệu Word có ${item.imageCount} hình ảnh)`;
            }
            return itemText;
        }).join('\n\n');

        const prompt = [
            'Bạn là trợ lý AI hỗ trợ hỏi đáp các báo cáo được lưu trữ.',
            'Luôn trả lời bằng tiếng Việt, chỉ sử dụng thông tin trong dữ liệu được cung cấp .',
            'Nếu dữ liệu không đủ, hãy nói rõ và gợi ý người dùng kiểm tra lại sau.',
            'Dữ liệu:',
            context || 'Không có dữ liệu',
            `Câu hỏi: ${question}`,
            'Câu trả lời chi tiết:'
        ].join('\n\n');

        const result = await geminiModel.generateContent(prompt);
        const answer = result && result.response && typeof result.response.text === 'function'
            ? result.response.text()
            : '';

        res.json({
            answer: answer && answer.trim().length > 0 ? answer : 'Tôi chưa tìm thấy thông tin phù hợp trong dữ liệu hiện có.',
            references: relevantData.map(item => ({
                id: item._id,
                title: item.title,
                content: item.content,
                fileType: item.fileType,
                htmlContent: item.htmlContent,
                imageCount: item.imageCount,
                date: item.date
            }))
        });
    } catch (err) {
        console.error('Gemini API error:', err);
        res.status(500).json({ error: 'Không thể xử lý yêu cầu. Vui lòng thử lại.' });
    }
});

// ============================================
// CAROUSEL ROUTES
// ============================================

// Get carousel images
app.get('/api/carousel', async (req, res) => {
    try {
        const images = await CarouselImage.find().sort({ order: 1 });
        res.json(images);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Add carousel image
app.post('/api/carousel', async (req, res) => {
    try {
        const { title, imageUrl, alt, order } = req.body;
        const newImage = new CarouselImage({ title, imageUrl, alt, order: order || 0 });
        await newImage.save();
        res.json(newImage);
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// Upload carousel image
app.post('/api/carousel/upload', upload.single('image'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No image file provided' });
        }

        const { title, alt, order } = req.body;
        const imageUrl = `/uploads/${req.file.filename}`;

        const newImage = new CarouselImage({
            title: title || 'Untitled',
            imageUrl: imageUrl,
            alt: alt || '',
            order: order || 0
        });

        await newImage.save();
        console.log(`✅ Uploaded carousel image: "${newImage.title}"`);
        
        res.json({
            success: true,
            message: 'Image uploaded successfully',
            data: newImage
        });
    } catch (err) {
        // Clean up uploaded file if DB save fails
        if (req.file) {
            fs.unlink(req.file.path, () => {});
        }
        res.status(400).json({ error: err.message });
    }
});

// Upload carousel image with base64
app.post('/api/carousel/upload-base64', async (req, res) => {
    try {
        const { title, imageData, alt, order } = req.body;

        if (!imageData) {
            return res.status(400).json({ error: 'No image data provided' });
        }

        // Remove data:image/...;base64, prefix if exists
        const base64Data = imageData.replace(/^data:image\/\w+;base64,/, '');
        const filename = `base64-${Date.now()}-${Math.round(Math.random() * 1E9)}.png`;
        const filepath = path.join(uploadDir, filename);

        // Write base64 to file
        fs.writeFileSync(filepath, Buffer.from(base64Data, 'base64'));

        const imageUrl = `/uploads/${filename}`;

        const newImage = new CarouselImage({
            title: title || 'Untitled',
            imageUrl: imageUrl,
            alt: alt || '',
            order: order || 0
        });

        await newImage.save();
        res.json({
            success: true,
            message: 'Image uploaded successfully',
            data: newImage
        });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// Delete carousel image
app.delete('/api/carousel/:id', async (req, res) => {
    try {
        const image = await CarouselImage.findByIdAndDelete(req.params.id);
        
        // Delete image file from server if it exists
        if (image && image.imageUrl && image.imageUrl.startsWith('/uploads/')) {
            const filepath = path.join(__dirname, image.imageUrl);
            fs.unlink(filepath, (err) => {
                if (err) console.error('Error deleting file:', err);
            });
        }
        
        console.log(`🗑️ Deleted carousel image: "${image ? image.title : 'Unknown'}"`);
        res.json({ message: 'Deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============================================
// SERVE FRONTEND FILES
// ============================================

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin-chat-word-full.html'));
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// ============================================
// START SERVER
// ============================================

app.listen(PORT, () => {
    console.log(`
╔════════════════════════════════════════════╗
║   🚀 AI Chat Admin Server Started         ║
║                                            ║
║   📡 Port: ${PORT}                            ║
║   🗄️  Database: MongoDB                    ║
║   📄 Word Support: ✅ Enabled              ║
║   🔐 Authentication: ✅ Enabled            ║
║                                            ║
║   Endpoints:                               ║
║   • POST   /api/auth/login                ║
║   • POST   /api/auth/logout               ║
║   • GET    /api/auth/check                ║
║   • GET    /api/users (admin)             ║
║   • POST   /api/users (admin)             ║
║   • DELETE /api/users/:id (admin)         ║
║   • GET    /api/data                      ║
║   • POST   /api/data                      ║
║   • DELETE /api/data/:id                  ║
║   • POST   /api/ask                       ║
║   • GET    /api/carousel                  ║
║   • POST   /api/carousel/upload           ║
║   • DELETE /api/carousel/:id              ║
║                                            ║
║   Pages:                                   ║
║   • GET /login   → Login page             ║
║   • GET /admin   → Admin panel            ║
║   • GET /        → Public page            ║
║                                            ║
║   Open: http://localhost:${PORT}/login      ║
╚════════════════════════════════════════════╝
    `);
});