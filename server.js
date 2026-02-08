const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Подключение к MongoDB
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/smartphone_course', {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log('Connected to MongoDB');
}).catch(err => {
    console.error('MongoDB connection error:', err);
});

// Схемы Mongoose
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    email: { type: String, default: '' },
    isAdmin: { type: Boolean, default: false },
    isSuperAdmin: { type: Boolean, default: false },
    beginnerLessonCompleted: { type: Boolean, default: false },
    beginnerTestPassed: { type: Boolean, default: false },
    advancedLessonCompleted: { type: Boolean, default: false },
    advancedTestPassed: { type: Boolean, default: false },
    registered: { type: Date, default: Date.now }
});

const LessonSchema = new mongoose.Schema({
    level: { type: String, enum: ['beginner', 'advanced'], required: true },
    title: { type: String, required: true },
    content: { type: String, required: true },
    icon: { type: String, default: 'fa-mobile-alt' },
    order: { type: Number, default: 0 },
    videoEmbedCode: { type: String, default: '' },
    hasCustomVideo: { type: Boolean, default: false }
});

const TestSchema = new mongoose.Schema({
    level: { type: String, enum: ['beginner', 'advanced'], required: true },
    questions: [{
        question: { type: String, required: true },
        options: [{
            id: { type: String, required: true },
            text: { type: String, required: true },
            correct: { type: Boolean, default: false }
        }]
    }]
});

// Модели
const User = mongoose.model('User', UserSchema);
const Lesson = mongoose.model('Lesson', LessonSchema);
const Test = mongoose.model('Test', TestSchema);

// Middleware для проверки JWT токена
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.status(401).json({ error: 'Требуется авторизация' });
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Неверный токен' });
        req.user = user;
        next();
    });
};

// Middleware для проверки админских прав
const isAdmin = (req, res, next) => {
    if (!req.user.isAdmin) {
        return res.status(403).json({ error: 'Требуются права администратора' });
    }
    next();
};

// Маршруты пользователей
app.post('/api/register', async (req, res) => {
    try {
        const { name, password, email } = req.body;
        
        // Проверка существующего пользователя
        const existingUser = await User.findOne({ name });
        if (existingUser) {
            return res.status(400).json({ error: 'Пользователь с таким именем уже существует' });
        }
        
        // Хеширование пароля
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Создание пользователя
        const user = new User({
            name,
            password: hashedPassword,
            email: email || '',
            isAdmin: false
        });
        
        await user.save();
        
        // Создание JWT токена
        const token = jwt.sign(
            { id: user._id, name: user.name, isAdmin: user.isAdmin },
            JWT_SECRET,
            { expiresIn: '7d' }
        );
        
        res.status(201).json({
            message: 'Пользователь успешно зарегистрирован',
            token,
            user: {
                id: user._id,
                name: user.name,
                isAdmin: user.isAdmin,
                beginnerLessonCompleted: user.beginnerLessonCompleted,
                beginnerTestPassed: user.beginnerTestPassed,
                advancedLessonCompleted: user.advancedLessonCompleted,
                advancedTestPassed: user.advancedTestPassed
            }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Ошибка сервера при регистрации' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { name, password } = req.body;
        
        // Поиск пользователя
        const user = await User.findOne({ name });
        if (!user) {
            return res.status(401).json({ error: 'Неверное имя пользователя или пароль' });
        }
        
        // Проверка пароля
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Неверное имя пользователя или пароль' });
        }
        
        // Создание JWT токена
        const token = jwt.sign(
            { id: user._id, name: user.name, isAdmin: user.isAdmin },
            JWT_SECRET,
            { expiresIn: '7d' }
        );
        
        res.json({
            message: 'Успешный вход',
            token,
            user: {
                id: user._id,
                name: user.name,
                isAdmin: user.isAdmin,
                beginnerLessonCompleted: user.beginnerLessonCompleted,
                beginnerTestPassed: user.beginnerTestPassed,
                advancedLessonCompleted: user.advancedLessonCompleted,
                advancedTestPassed: user.advancedTestPassed
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Ошибка сервера при входе' });
    }
});

app.get('/api/me', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        if (!user) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }
        res.json({ user });
    } catch (error) {
        console.error('Get user error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.put('/api/user/progress', authenticateToken, async (req, res) => {
    try {
        const { beginnerLessonCompleted, beginnerTestPassed, advancedLessonCompleted, advancedTestPassed } = req.body;
        
        const updateData = {};
        if (beginnerLessonCompleted !== undefined) updateData.beginnerLessonCompleted = beginnerLessonCompleted;
        if (beginnerTestPassed !== undefined) updateData.beginnerTestPassed = beginnerTestPassed;
        if (advancedLessonCompleted !== undefined) updateData.advancedLessonCompleted = advancedLessonCompleted;
        if (advancedTestPassed !== undefined) updateData.advancedTestPassed = advancedTestPassed;
        
        const user = await User.findByIdAndUpdate(
            req.user.id,
            { $set: updateData },
            { new: true }
        ).select('-password');
        
        res.json({
            message: 'Прогресс обновлен',
            user
        });
    } catch (error) {
        console.error('Update progress error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Маршруты уроков
app.get('/api/lessons/:level', async (req, res) => {
    try {
        const { level } = req.params;
        const lessons = await Lesson.find({ level }).sort({ order: 1 });
        res.json({ lessons });
    } catch (error) {
        console.error('Get lessons error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.put('/api/lessons/:level', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { level } = req.params;
        const lessons = req.body.lessons;
        
        // Удаляем старые уроки для этого уровня
        await Lesson.deleteMany({ level });
        
        // Создаем новые уроки
        const newLessons = lessons.map((lesson, index) => ({
            ...lesson,
            level,
            order: index
        }));
        
        await Lesson.insertMany(newLessons);
        
        res.json({ message: 'Уроки успешно обновлены' });
    } catch (error) {
        console.error('Update lessons error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Маршруты тестов
app.get('/api/tests/:level', async (req, res) => {
    try {
        const { level } = req.params;
        const test = await Test.findOne({ level });
        res.json({ test });
    } catch (error) {
        console.error('Get test error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.put('/api/tests/:level', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { level } = req.params;
        const { questions } = req.body;
        
        // Ищем существующий тест
        let test = await Test.findOne({ level });
        
        if (test) {
            // Обновляем существующий тест
            test.questions = questions;
            await test.save();
        } else {
            // Создаем новый тест
            test = new Test({ level, questions });
            await test.save();
        }
        
        res.json({ message: 'Тест успешно обновлен' });
    } catch (error) {
        console.error('Update test error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Маршрут для получения всех пользователей (только для админов)
app.get('/api/admin/users', authenticateToken, isAdmin, async (req, res) => {
    try {
        const users = await User.find({}, '-password').sort({ registered: -1 });
        res.json({ users });
    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Проверка подключения
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: 'Сервер работает' });
});

// Запуск сервера
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});