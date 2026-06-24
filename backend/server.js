/**
 * =====================================================
 *  SPHINX UNIVERSITY – BACKEND SERVER
 *  server.js – ONE FILE: All routes, models, auth, DB
 *  Youssef Sobhy Mohamed Redwan | Class of 2027
 * =====================================================
 */

require('dotenv').config();
const express    = require('express');
const mongoose   = require('mongoose');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const cors       = require('cors');
const path       = require('path');

const app  = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET  = process.env.JWT_SECRET  || 'sphinx_university_secret_key_2027';
const JWT_EXPIRE  = process.env.JWT_EXPIRE  || '7d';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/sphinx_university';

/* =====================================================
   MIDDLEWARE
===================================================== */
app.use(cors({
  origin: '*',
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization']
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Serve static files (HTML pages) from root directory
app.use(express.static(path.join(__dirname, '..')));

/* =====================================================
   DATABASE CONNECTION
===================================================== */
mongoose.connect(MONGODB_URI)
  .then(() => console.log('✅ MongoDB connected:', MONGODB_URI))
  .catch(err => {
    console.error('❌ MongoDB connection error:', err.message);
    console.log('⚠️  Server running without database (demo mode)');
  });

/* =====================================================
   USER SCHEMA & MODEL
===================================================== */
const userSchema = new mongoose.Schema({
  fullName: {
    type: String, required: true, trim: true,
    minlength: 3, maxlength: 50,
    validate: {
      validator: v => /^[\u0600-\u06FFa-zA-Z\s]+$/.test(v.trim()),
      message: 'الاسم يجب أن يحتوي على حروف فقط'
    }
  },
  fatherName: {
    type: String, required: true, trim: true,
    validate: {
      validator: v => /^[\u0600-\u06FFa-zA-Z\s]+$/.test(v.trim()),
      message: 'اسم الأب يجب أن يحتوي على حروف فقط'
    }
  },
  phone: {
    type: String, required: true, unique: true, trim: true,
    validate: {
      validator: v => /^(010|011|012|015)\d{8}$/.test(v),
      message: 'رقم الهاتف يجب أن يبدأ بـ 010/011/012/015 ويكون 11 رقم'
    }
  },
  universityId: {
    type: String, required: true, unique: true, trim: true,
    immutable: true,
    validate: {
      validator: v => /^42510\d{3}$/.test(v),
      message: 'الرقم الجامعي يجب أن يبدأ بـ 42510 ويكون 8 أرقام'
    }
  },
  email:          { type: String, default: '', trim: true, lowercase: true },
  password:       { type: String, required: true, minlength: 6 },
  profilePicture: { type: String, default: 'imgs/profile.jpg' },
  createdAt:      { type: Date, default: Date.now },
  lastLogin:      { type: Date },
  progress: {
    networks:     { type: Number, default: 0, min: 0, max: 100 },
    architecture: { type: Number, default: 0, min: 0, max: 100 },
    dsa:          { type: Number, default: 0, min: 0, max: 100 }
  },
  totalPoints:    { type: Number, default: 0 },
  studySessions:  { type: Number, default: 0 },
  totalStudyTime: { type: Number, default: 0 },
  achievements: [{
    name:       { type: String },
    unlockedAt: { type: Date, default: Date.now },
    icon:       { type: String }
  }],
  isActive:  { type: Boolean, default: true },
  darkMode:  { type: Boolean, default: false }
});

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

// Method to compare passwords
userSchema.methods.comparePassword = async function(candidate) {
  return bcrypt.compare(candidate, this.password);
};

// Method to get public profile (no password)
userSchema.methods.toPublic = function() {
  const obj = this.toObject();
  delete obj.password;
  return obj;
};

const User = mongoose.model('User', userSchema);

/* =====================================================
   AUTH MIDDLEWARE
===================================================== */
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'غير مصرح – يجب تسجيل الدخول' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'جلسة منتهية – يرجى تسجيل الدخول مرة أخرى' });
  }
}

/* =====================================================
   HELPERS
===================================================== */
function generateToken(userId) {
  return jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: JWT_EXPIRE });
}

function validationError(errors) {
  const messages = Object.values(errors).map(e => e.message);
  return messages.join(', ');
}

function calcAvgProgress(progress = {}) {
  const { networks = 0, architecture = 0, dsa = 0 } = progress;
  return Math.round((networks + architecture + dsa) / 3);
}

/* =====================================================
   ROUTES: AUTH
===================================================== */

/**
 * POST /api/auth/register
 * Create new account
 */
app.post('/api/auth/register', async (req, res) => {
  try {
    const { fullName, fatherName, phone, universityId, password } = req.body;

    // Basic checks
    if (!fullName || !fatherName || !phone || !universityId || !password) {
      return res.status(400).json({ message: 'جميع الحقول المطلوبة يجب ملؤها' });
    }
    if (password.length < 6) {
      return res.status(400).json({ message: 'كلمة السر يجب أن تكون 6 أحرف على الأقل' });
    }
    if (!/^42510\d{3}$/.test(universityId)) {
      return res.status(400).json({ message: 'الرقم الجامعي يجب أن يبدأ بـ 42510 ويكون 8 أرقام' });
    }
    if (!/^(010|011|012|015)\d{8}$/.test(phone)) {
      return res.status(400).json({ message: 'رقم الهاتف غير صحيح' });
    }

    // Check duplicates
    const existing = await User.findOne({ $or: [{ phone }, { universityId }] });
    if (existing) {
      if (existing.phone === phone) {
        return res.status(409).json({ message: 'رقم الهاتف مسجل بالفعل' });
      }
      return res.status(409).json({ message: 'الرقم الجامعي مسجل بالفعل' });
    }

    const user = new User({ fullName, fatherName, phone, universityId, password });
    await user.save();

    // Award "First Login" achievement
    user.achievements.push({ name: 'First Login', icon: '👋', unlockedAt: new Date() });
    user.lastLogin = new Date();
    user.totalPoints += 10;
    await user.save();

    const token = generateToken(user._id);
    res.status(201).json({
      message: 'تم إنشاء الحساب بنجاح',
      token,
      user: user.toPublic()
    });
  } catch (err) {
    if (err.name === 'ValidationError') {
      return res.status(400).json({ message: validationError(err.errors) });
    }
    if (err.code === 11000) {
      const field = Object.keys(err.keyValue)[0];
      const msg = field === 'phone' ? 'رقم الهاتف مسجل بالفعل' : 'الرقم الجامعي مسجل بالفعل';
      return res.status(409).json({ message: msg });
    }
    console.error('Register error:', err);
    res.status(500).json({ message: 'خطأ في الخادم – حاول مرة أخرى' });
  }
});

/**
 * POST /api/auth/login
 * Login with phone OR universityId + password
 */
app.post('/api/auth/login', async (req, res) => {
  try {
    const { identifier, password } = req.body;
    if (!identifier || !password) {
      return res.status(400).json({ message: 'يجب إدخال رقم الهاتف أو الرقم الجامعي وكلمة السر' });
    }

    // Find user by phone or universityId
    const user = await User.findOne({
      $or: [{ phone: identifier }, { universityId: identifier }],
      isActive: true
    });

    if (!user) {
      return res.status(401).json({ message: 'بيانات تسجيل الدخول غير صحيحة' });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ message: 'كلمة السر غير صحيحة' });
    }

    // Update last login and award points
    user.lastLogin = new Date();
    user.totalPoints += 5;
    user.studySessions += 1;

    // Check for "First Login" achievement
    const hasFirstLogin = user.achievements.some(a => a.name === 'First Login');
    if (!hasFirstLogin) {
      user.achievements.push({ name: 'First Login', icon: '👋', unlockedAt: new Date() });
    }

    await user.save();

    const token = generateToken(user._id);
    res.json({
      message: 'تم تسجيل الدخول بنجاح',
      token,
      user: user.toPublic()
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

/**
 * POST /api/auth/logout
 * Logout (JWT is stateless; client deletes token)
 */
app.post('/api/auth/logout', authMiddleware, async (req, res) => {
  try {
    // Could add token to blacklist in Redis here for full logout support
    res.json({ message: 'تم تسجيل الخروج بنجاح' });
  } catch (err) {
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

/* =====================================================
   ROUTES: USERS
===================================================== */

/**
 * GET /api/users/me
 * Get current user profile
 */
app.get('/api/users/me', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    if (!user) return res.status(404).json({ message: 'المستخدم غير موجود' });
    res.json(user);
  } catch (err) {
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

/**
 * PUT /api/users/me
 * Update user profile (name, fatherName, phone, email)
 */
app.put('/api/users/me', authMiddleware, async (req, res) => {
  try {
    const { fullName, fatherName, phone, email } = req.body;
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ message: 'المستخدم غير موجود' });

    // Validate
    if (fullName && fullName.trim().length < 3) {
      return res.status(400).json({ message: 'الاسم يجب أن يكون 3 أحرف على الأقل' });
    }
    if (phone && !/^(010|011|012|015)\d{8}$/.test(phone)) {
      return res.status(400).json({ message: 'رقم الهاتف غير صحيح' });
    }
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ message: 'البريد الإلكتروني غير صحيح' });
    }

    // Check phone uniqueness
    if (phone && phone !== user.phone) {
      const existingPhone = await User.findOne({ phone, _id: { $ne: req.userId } });
      if (existingPhone) return res.status(409).json({ message: 'رقم الهاتف مستخدم بالفعل' });
    }

    if (fullName) user.fullName = fullName.trim();
    if (fatherName) user.fatherName = fatherName.trim();
    if (phone) user.phone = phone.trim();
    if (email !== undefined) user.email = email.trim();

    // Check "Profile Set" achievement
    const hasProfile = user.achievements.some(a => a.name === 'Profile Set');
    if (!hasProfile && user.fullName && user.fatherName && user.phone && user.email) {
      user.achievements.push({ name: 'Profile Set', icon: '✅', unlockedAt: new Date() });
      user.totalPoints += 20;
    }

    await user.save();
    res.json({ message: 'تم تحديث البيانات بنجاح', user: user.toPublic() });
  } catch (err) {
    if (err.name === 'ValidationError') {
      return res.status(400).json({ message: validationError(err.errors) });
    }
    console.error('Update user error:', err);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

/**
 * PUT /api/users/me/password
 * Change password
 */
app.put('/api/users/me/password', authMiddleware, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ message: 'جميع الحقول مطلوبة' });
    }
    if (newPassword.length < 6) {
      return res.status(400).json({ message: 'كلمة السر الجديدة يجب أن تكون 6 أحرف على الأقل' });
    }

    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ message: 'المستخدم غير موجود' });

    const isMatch = await user.comparePassword(currentPassword);
    if (!isMatch) return res.status(401).json({ message: 'كلمة السر الحالية غير صحيحة – incorrect' });

    user.password = newPassword; // pre-save hook will hash
    await user.save();
    res.json({ message: 'تم تغيير كلمة السر بنجاح' });
  } catch (err) {
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

/**
 * POST /api/users/me/photo
 * Upload profile photo (base64)
 */
app.post('/api/users/me/photo', authMiddleware, async (req, res) => {
  try {
    const { photo } = req.body;
    if (!photo) return res.status(400).json({ message: 'الصورة مطلوبة' });

    // Validate base64 image
    if (!photo.startsWith('data:image/')) {
      return res.status(400).json({ message: 'صيغة الصورة غير صحيحة' });
    }

    // Estimate size (base64 is ~4/3 of original)
    const sizeInBytes = (photo.length * 3) / 4;
    if (sizeInBytes > 5 * 1024 * 1024) {
      return res.status(400).json({ message: 'الصورة يجب أن تكون أقل من 5MB' });
    }

    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ message: 'المستخدم غير موجود' });

    user.profilePicture = photo;
    user.totalPoints += 10;

    // Check "Photo Uploaded" achievement
    const hasPhoto = user.achievements.some(a => a.name === 'Photo Uploaded');
    if (!hasPhoto) {
      user.achievements.push({ name: 'Photo Uploaded', icon: '📸', unlockedAt: new Date() });
    }

    await user.save();
    res.json({ message: 'تم تحديث الصورة بنجاح', profilePicture: photo });
  } catch (err) {
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

/* =====================================================
   ROUTES: PROGRESS
===================================================== */

/**
 * PUT /api/progress
 * Update course progress
 */
app.put('/api/progress', authMiddleware, async (req, res) => {
  try {
    const { course, value } = req.body;
    const validCourses = ['networks', 'architecture', 'dsa'];
    if (!validCourses.includes(course)) {
      return res.status(400).json({ message: 'كورس غير صحيح' });
    }
    if (typeof value !== 'number' || value < 0 || value > 100) {
      return res.status(400).json({ message: 'القيمة يجب أن تكون بين 0 و 100' });
    }

    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ message: 'المستخدم غير موجود' });

    const oldVal = user.progress[course] || 0;
    user.progress[course] = value;

    // Award points for progress
    if (value > oldVal) {
      user.totalPoints += Math.round((value - oldVal) * 0.5);
    }

    // Check achievements
    const newAchievements = [];

    if (course === 'networks' && value >= 25) {
      const has = user.achievements.some(a => a.name === 'Network Cadet');
      if (!has) { user.achievements.push({ name: 'Network Cadet', icon: '🌐', unlockedAt: new Date() }); newAchievements.push('Network Cadet 🌐'); user.totalPoints += 15; }
    }
    if (course === 'architecture' && value >= 25) {
      const has = user.achievements.some(a => a.name === 'Chip Explorer');
      if (!has) { user.achievements.push({ name: 'Chip Explorer', icon: '⚙️', unlockedAt: new Date() }); newAchievements.push('Chip Explorer ⚙️'); user.totalPoints += 15; }
    }
    if (course === 'dsa' && value >= 50) {
      const has = user.achievements.some(a => a.name === 'DSA Climber');
      if (!has) { user.achievements.push({ name: 'DSA Climber', icon: '🌳', unlockedAt: new Date() }); newAchievements.push('DSA Climber 🌳'); user.totalPoints += 20; }
    }
    if (course === 'dsa' && value >= 75) {
      const has = user.achievements.some(a => a.name === 'Algorithm Pro');
      if (!has) { user.achievements.push({ name: 'Algorithm Pro', icon: '💡', unlockedAt: new Date() }); newAchievements.push('Algorithm Pro 💡'); user.totalPoints += 30; }
    }

    // Multi-tasker achievement
    if (user.progress.networks > 0 && user.progress.architecture > 0 && user.progress.dsa > 0) {
      const has = user.achievements.some(a => a.name === 'Multi-tasker');
      if (!has) { user.achievements.push({ name: 'Multi-tasker', icon: '🎯', unlockedAt: new Date() }); newAchievements.push('Multi-tasker 🎯'); user.totalPoints += 25; }
    }

    await user.save();
    res.json({
      message: 'تم تحديث التقدم',
      progress: user.progress,
      totalPoints: user.totalPoints,
      newAchievements
    });
  } catch (err) {
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

/* =====================================================
   ROUTES: ACHIEVEMENTS
===================================================== */

/**
 * POST /api/achievements/check
 * Check and unlock achievements based on action
 */
app.post('/api/achievements/check', authMiddleware, async (req, res) => {
  try {
    const { action } = req.body;
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ message: 'المستخدم غير موجود' });

    const newAchievements = [];
    const hasAchievement = (name) => user.achievements.some(a => a.name === name);
    const addAchievement = (name, icon, points = 10) => {
      if (!hasAchievement(name)) {
        user.achievements.push({ name, icon, unlockedAt: new Date() });
        user.totalPoints += points;
        newAchievements.push({ name, icon });
      }
    };

    // Action-based achievement checks
    switch (action) {
      case 'pomodoro_complete':
        user.studySessions = (user.studySessions || 0) + 1;
        addAchievement('First Focus', '🍅', 10);
        if (user.studySessions >= 5) addAchievement('On Fire!', '🔥', 25);
        break;
      case 'note_saved':
        addAchievement('Note Keeper', '📝', 10);
        break;
      case 'dark_mode_enabled':
        addAchievement('Night Owl', '🌙', 5);
        break;
      case 'profile_complete':
        if (user.fullName && user.phone && user.email) addAchievement('Profile Set', '✅', 20);
        break;
      case 'photo_uploaded':
        addAchievement('Photo Uploaded', '📸', 10);
        break;
    }

    if (newAchievements.length > 0) {
      await user.save();
    }

    res.json({
      newAchievements,
      totalAchievements: user.achievements.length,
      totalPoints: user.totalPoints
    });
  } catch (err) {
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

/* =====================================================
   ROUTES: LEADERBOARD
===================================================== */

/**
 * GET /api/leaderboard
 * Get top students sorted by totalPoints
 */
app.get('/api/leaderboard', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 20;
    const users = await User.find({ isActive: true })
      .select('fullName profilePicture totalPoints progress achievements studySessions universityId')
      .sort({ totalPoints: -1 })
      .limit(limit);

    const leaderboard = users.map((u, index) => ({
      rank: index + 1,
      id: u._id,
      fullName: u.fullName,
      profilePicture: u.profilePicture,
      totalPoints: u.totalPoints,
      avgProgress: calcAvgProgress(u.progress),
      achievementsCount: u.achievements.length,
      studySessions: u.studySessions,
      universityId: u.universityId
    }));

    res.json(leaderboard);
  } catch (err) {
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

/* =====================================================
   ROUTES: STUDY SESSIONS
===================================================== */

/**
 * POST /api/study/session
 * Record a completed study session
 */
app.post('/api/study/session', authMiddleware, async (req, res) => {
  try {
    const { duration } = req.body; // duration in minutes
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ message: 'المستخدم غير موجود' });

    user.studySessions = (user.studySessions || 0) + 1;
    user.totalStudyTime = (user.totalStudyTime || 0) + (duration || 25);
    user.totalPoints += 5;

    // Achievements
    if (!user.achievements.some(a => a.name === 'First Focus')) {
      user.achievements.push({ name: 'First Focus', icon: '🍅', unlockedAt: new Date() });
      user.totalPoints += 10;
    }
    if (user.studySessions >= 5 && !user.achievements.some(a => a.name === 'On Fire!')) {
      user.achievements.push({ name: 'On Fire!', icon: '🔥', unlockedAt: new Date() });
      user.totalPoints += 25;
    }

    await user.save();
    res.json({
      message: 'تم تسجيل جلسة المذاكرة',
      studySessions: user.studySessions,
      totalStudyTime: user.totalStudyTime,
      totalPoints: user.totalPoints
    });
  } catch (err) {
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

/* =====================================================
   ROUTES: HEALTH CHECK
===================================================== */
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    server: 'Sphinx University API',
    version: '1.0.0',
    time: new Date().toISOString(),
    db: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

/* =====================================================
   ROUTES: STATS (Admin-style overview)
===================================================== */
app.get('/api/stats', authMiddleware, async (req, res) => {
  try {
    const [totalUsers, totalSessions] = await Promise.all([
      User.countDocuments({ isActive: true }),
      User.aggregate([{ $group: { _id: null, total: { $sum: '$studySessions' } } }])
    ]);
    res.json({
      totalUsers,
      totalStudySessions: totalSessions[0]?.total || 0
    });
  } catch (err) {
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

/* =====================================================
   ERROR HANDLING MIDDLEWARE
===================================================== */
app.use((req, res) => {
  res.status(404).json({ message: `المسار ${req.originalUrl} غير موجود` });
});

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ message: 'خطأ غير متوقع في الخادم' });
});

/* =====================================================
   START SERVER
===================================================== */
app.listen(PORT, () => {
  console.log('');
  console.log('╔══════════════════════════════════════════════╗');
  console.log('║   🎓 SPHINX UNIVERSITY SERVER STARTED        ║');
  console.log('║   Youssef Sobhy Mohamed Redwan               ║');
  console.log('╠══════════════════════════════════════════════╣');
  console.log(`║   🚀 Port:     ${PORT}                          ║`);
  console.log(`║   🌐 API:      http://localhost:${PORT}/api       ║`);
  console.log(`║   💚 Health:   http://localhost:${PORT}/api/health║`);
  console.log('╠══════════════════════════════════════════════╣');
  console.log('║   📚 Routes Available:                       ║');
  console.log('║   POST  /api/auth/register                   ║');
  console.log('║   POST  /api/auth/login                      ║');
  console.log('║   POST  /api/auth/logout                     ║');
  console.log('║   GET   /api/users/me                        ║');
  console.log('║   PUT   /api/users/me                        ║');
  console.log('║   PUT   /api/users/me/password               ║');
  console.log('║   POST  /api/users/me/photo                  ║');
  console.log('║   PUT   /api/progress                        ║');
  console.log('║   POST  /api/achievements/check              ║');
  console.log('║   GET   /api/leaderboard                     ║');
  console.log('║   POST  /api/study/session                   ║');
  console.log('╚══════════════════════════════════════════════╝');
  console.log('');
});

module.exports = app;
