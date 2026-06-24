# 🎓 Sphinx University Platform

**المطور:** يوسف صبحي محمد رضوان | Class of 2027  
**الكلية:** Faculty of Computers & AI – Sphinx University, Assiut

---

## 📁 Project Structure

```
sphinx-university/
├── index.html          ← الصفحة الرئيسية (مع كل CSS و JS)
├── login.html          ← صفحة تسجيل الدخول (مع كل CSS و JS)
├── profile.html        ← صفحة الملف الشخصي (مع كل CSS و JS)
├── backend/
│   └── server.js       ← الخادم الكامل (Routes + DB + Auth + Models)
├── imgs/
│   └── profile.jpg     ← الصورة الشخصية الافتراضية
├── package.json
├── .env
└── README.md
```

---

## 🚀 تشغيل المشروع

### 1. المتطلبات
- Node.js v14 أو أحدث
- MongoDB (مثبت ويعمل محلياً)

### 2. التثبيت
```bash
# في مجلد المشروع
npm install
```

### 3. تشغيل MongoDB
```bash
# Windows
mongod

# macOS / Linux
sudo systemctl start mongod
```

### 4. تشغيل الخادم
```bash
# Production
npm start

# Development (مع auto-reload)
npm run dev
```

### 5. فتح المنصة
- افتح `index.html` في المتصفح
- أو اذهب إلى: `http://localhost:5000`

---

## 🔑 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | إنشاء حساب جديد |
| POST | `/api/auth/login` | تسجيل الدخول |
| POST | `/api/auth/logout` | تسجيل الخروج |
| GET  | `/api/users/me` | بيانات المستخدم الحالي |
| PUT  | `/api/users/me` | تحديث البيانات الشخصية |
| PUT  | `/api/users/me/password` | تغيير كلمة السر |
| POST | `/api/users/me/photo` | رفع الصورة الشخصية |
| PUT  | `/api/progress` | تحديث تقدم الكورسات |
| POST | `/api/achievements/check` | فحص الإنجازات |
| GET  | `/api/leaderboard` | لوحة المتصدرين |
| POST | `/api/study/session` | تسجيل جلسة مذاكرة |
| GET  | `/api/health` | فحص حالة الخادم |

---

## ✅ Validation Rules

| Field | Rule |
|-------|------|
| University ID | يبدأ بـ 42510 + 3 أرقام = 8 أرقام إجمالاً |
| Phone | 11 رقم يبدأ بـ 010 / 011 / 012 / 015 |
| Password | 6 أحرف على الأقل |
| Full Name | حروف عربية أو إنجليزية فقط، 3-50 حرف |

---

## 🏆 Achievements (12 إنجاز)

| # | Name | Icon | Condition |
|---|------|------|-----------|
| 1 | First Login | 👋 | أول تسجيل دخول |
| 2 | Profile Set | ✅ | اكتمال الملف الشخصي |
| 3 | Photo Uploaded | 📸 | رفع صورة شخصية |
| 4 | Note Keeper | 📝 | حفظ أول ملاحظة |
| 5 | First Focus | 🍅 | إتمام أول جلسة Pomodoro |
| 6 | On Fire! | 🔥 | 5 جلسات Pomodoro |
| 7 | Network Cadet | 🌐 | تقدم Networks ≥ 25% |
| 8 | Chip Explorer | ⚙️ | تقدم Architecture ≥ 25% |
| 9 | DSA Climber | 🌳 | تقدم DSA ≥ 50% |
| 10 | Algorithm Pro | 💡 | تقدم DSA ≥ 75% |
| 11 | Night Owl | 🌙 | تفعيل الوضع الداكن |
| 12 | Multi-tasker | 🎯 | تقدم في الكورسات الثلاثة |

---

## 📞 التواصل

- **WhatsApp:** https://wa.me/201202226786
- **Facebook:** https://www.facebook.com/share/18tR5k1aD9/
- **YouTube:** https://www.youtube.com/@YOUSSEFSOBHY1

---

© 2027 Sphinx University · Faculty of Computers & AI · Assiut  
Built with ❤️ by Youssef Sobhy Mohamed Redwan
