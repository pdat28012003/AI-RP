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
        const allowedMimes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
        if (allowedMimes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed'));
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
// UPDATED Schema - Support Word Documents
// ============================================
const ChatDataSchema = new mongoose.Schema({
    title: { type: String, required: true },
    content: { type: String, required: true },
    fileType: { type: String, enum: ['text', 'word'], default: 'text' },
    htmlContent: { type: String, default: null },
    imageCount: { type: Number, default: 0 },
    date: { type: String, default: () => new Date().toLocaleString('vi-VN') },
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

const ChatData = mongoose.model('ChatData', ChatDataSchema);
const CarouselImage = mongoose.model('CarouselImage', CarouselImageSchema);

// ============================================
// DATA ROUTES - UPDATED for Word Support
// ============================================

// Get all data
app.get('/api/data', async (req, res) => {
    try {
        const data = await ChatData.find().sort({ createdAt: -1 });
        // Map _id to id for frontend compatibility, include new fields
        const formattedData = data.map(item => ({
            id: item._id,
            title: item.title,
            content: item.content,
            fileType: item.fileType || 'text',
            htmlContent: item.htmlContent,
            imageCount: item.imageCount || 0,
            date: item.date
        }));
        res.json(formattedData);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Add new data - UPDATED to support Word documents
app.post('/api/data', async (req, res) => {
    try {
        const { title, content, fileType, htmlContent, imageCount } = req.body;
        
        if (!title || !content) {
            return res.status(400).json({ error: 'Title and content are required' });
        }

        const newData = new ChatData({ 
            title, 
            content,
            fileType: fileType || 'text',
            htmlContent: htmlContent || null,
            imageCount: imageCount || 0
        });
        
        await newData.save();
        
        console.log(`✅ Saved new ${fileType || 'text'} data: "${title}"${imageCount > 0 ? ` with ${imageCount} images` : ''}`);
        
        res.json({
            id: newData._id,
            title: newData.title,
            content: newData.content,
            fileType: newData.fileType,
            htmlContent: newData.htmlContent,
            imageCount: newData.imageCount,
            date: newData.date
        });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// Delete data
app.delete('/api/data/:id', async (req, res) => {
    try {
        const deletedData = await ChatData.findByIdAndDelete(req.params.id);
        if (deletedData) {
            console.log(`🗑️ Deleted data: "${deletedData.title}"`);
        }
        res.json({ message: 'Deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// UPDATED Ask endpoint - support Word documents in context
app.post('/api/ask', async (req, res) => {
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
            $or: [
                { title: { $regex: regex } },
                { content: { $regex: regex } }
            ]
        }).limit(6);

        if (relevantData.length === 0) {
            relevantData = await ChatData.find().sort({ createdAt: -1 }).limit(6);
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
╔═══════════════════════════════════════╗
║   🚀 AI Chat Admin Server Started    ║
║                                       ║
║   📡 Port: ${PORT}                        ║
║   🗄️  Database: MongoDB               ║
║   📄 Word Support: ✅ Enabled         ║
║                                       ║
║   Endpoints:                          ║
║   • GET  /api/data                    ║
║   • POST /api/data (Word support)     ║
║   • DEL  /api/data/:id                ║
║   • POST /api/ask                     ║
║   • GET  /api/carousel                ║
║   • POST /api/carousel/upload         ║
║   • DEL  /api/carousel/:id            ║
║                                       ║
║   Open: http://localhost:${PORT}        ║
╚═══════════════════════════════════════╝
    `);
});