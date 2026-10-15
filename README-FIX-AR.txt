إصلاح تسجيل دخول Discord — NEON RP

الملفات:
- server.js: نسخة backend معدّلة تضيف GET /auth/discord و GET /auth/discord/callback و POST /api/auth/discord/session.
- FRONTEND-DISCORD-LOGIN.js.txt: جسر صغير يجب دمجه في ملف index.html الحالي حتى يقرأ الموقع تذكرة تسجيل الدخول ويملأ حقول Discord.
- .env.example: أسماء متغيرات البيئة المطلوبة.

خطوات FadeHost:
1) خذ نسخة احتياطية من server.js الحالي.
2) استبدل server.js بالملف الموجود هنا، وتأكد أن أمر التشغيل هو: npm start (أو node server.js).
3) تأكد من متغيرات البيئة:
   DISCORD_CLIENT_ID=Application ID من Discord Developer Portal
   DISCORD_CLIENT_SECRET=OAuth2 Client Secret من OAuth2 في Discord Developer Portal
   DISCORD_OAUTH_REDIRECT_URI=https://neon-rp.fadehost.app/auth/discord/callback
   SITE_URL=https://freefire5795in-bit.github.io/NEON-RP/
   ALLOWED_ORIGIN=https://freefire5795in-bit.github.io
   APPLICATION_SHARED_SECRET=سر عشوائي طويل لا يقل عن 32 حرفًا
4) في Discord Developer Portal > OAuth2 > Redirects أضف حرفيًا:
   https://neon-rp.fadehost.app/auth/discord/callback
5) أعد تشغيل الخدمة، وافتح:
   https://neon-rp.fadehost.app/health
   المفروض يظهر JSON فيه ok: true.
6) ادمج FRONTEND-DISCORD-LOGIN.js.txt في سكربت الموقع الحالي، وارفع index.html إلى GitHub Pages.
7) اختبر زر تسجيل الدخول من الموقع.

مهم:
- لا تضع DISCORD_CLIENT_SECRET أو DISCORD_BOT_TOKEN داخل HTML أو GitHub Pages.
- تسجيل الدخول وحده لا يمنح رتبة Discord. منح الرتب يبقى عبر نظام قبول التقديمات الموجود في البوت.
- هذه الملفات لا تنشر نفسها على FadeHost أو GitHub تلقائيًا؛ يجب رفعها وإعادة تشغيل الخدمة يدويًا.


ملف .env المرفق: تم وضع معرّفات السيرفر والقنوات والرتب وروابط الموقع المعروفة. ما زال يلزمك إدخال DISCORD_BOT_TOKEN وDISCORD_CLIENT_ID وDISCORD_CLIENT_SECRET الصحيحة من حسابك؛ لم تكن هذه القيم متاحة في المحادثة ولا يصح تخمينها. لا ترفع ملف .env إلى GitHub ولا ترسله لأي شخص.
