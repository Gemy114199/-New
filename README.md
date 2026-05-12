# زاجل سبيد — نظام إدارة الفروع

## خطوات الرفع على Railway

### 1. ارفع على GitHub
- افتح github.com واعمل مستودع جديد اسمه `zagel-server`
- ارفع كل الملفات

### 2. افتح Railway
- روح railway.app وسجل بحساب GitHub
- اضغط New Project → Deploy from GitHub
- اختار مستودع `zagel-server`

### 3. أضف قاعدة البيانات
- في المشروع اضغط + Add Service → Database → PostgreSQL
- Railway هيضيف DATABASE_URL تلقائياً

### 4. أضف متغير JWT_SECRET
- اضغط على السيرفر → Variables
- أضف: JWT_SECRET = zagel_secret_2026_change_me

### 5. انشر
- اضغط Deploy
- Railway هيديك رابط مثل: https://zagel-server.up.railway.app

## كلمات المرور الافتراضية
| الفرع | الباسورد |
|-------|----------|
| المحلة الكبرى | 1111 |
| المعادي | 2222 |
| المنصورة | 3333 |
| طنطا | 4444 |
| المدير العام | 9999 |
| اليومي | 1234 |
| الشهري | 5678 |
| السنوي | 9999y |
