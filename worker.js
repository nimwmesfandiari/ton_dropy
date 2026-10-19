export default {
  async fetch(request, env) {
    // تنظیمات CORS برای اینکه سایت شما (GitHub Pages) بتواند با این API ارتباط برقرار کند
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);

    try {
      // 1. مسیر ورود و اعتبارسنجی کاربر (از طریق Telegram Mini App)
      if (url.pathname === "/api/auth" && request.method === "POST") {
        const { initData } = await request.json();
        
        // اعتبارسنجی داده‌های تلگرام (جلوگیری از جعل هویت)
        const isValid = await validateTelegramWebAppData(initData, env.BOT_TOKEN);
        
        if (!isValid) {
          return new Response(JSON.stringify({ error: "Invalid Telegram Data" }), { status: 403, headers: corsHeaders });
        }

        // استخراج اطلاعات کاربر از initData
        const urlParams = new URLSearchParams(initData);
        const userJson = JSON.parse(urlParams.get('user'));
        const userId = userJson.id;
        const username = userJson.username || userJson.first_name || "User";

        // بررسی اینکه آیا کاربر در دیتابیس وجود دارد یا خیر
        let user = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(userId).first();

        if (!user) {
          // اگر کاربر جدید است، او را ثبت کن
          await env.DB.prepare("INSERT INTO users (id, username) VALUES (?, ?)").bind(userId, username).run();
          user = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(userId).first();
        }

        return new Response(JSON.stringify({ success: true, user }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      // 2. مسیر ثبت سفارش جدید
      if (url.pathname === "/api/order" && request.method === "POST") {
        const { userId, amountTon, amountIrt } = await request.json();
        
        // تولید یک شناسه یکتا برای سفارش
        const orderId = crypto.randomUUID();

        // ثبت سفارش در دیتابیس با وضعیت pending (در انتظار تایید)
        await env.DB.prepare(
          "INSERT INTO orders (id, user_id, amount_ton, amount_irt, status) VALUES (?, ?, ?, ?, 'pending')"
        ).bind(orderId, userId, amountTon, amountIrt).run();

        return new Response(JSON.stringify({ success: true, orderId }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      return new Response("Not Found", { status: 404, headers: corsHeaders });

    } catch (err) {
      // ایجنت امنیت: خطاهای داخلی نباید به کاربر نمایش داده شوند
      return new Response(JSON.stringify({ error: "Internal Server Error" }), { status: 500, headers: corsHeaders });
    }
  },
};

// تابع کمکی برای اعتبارسنجی هش تلگرام (امنیت بالا)
async function validateTelegramWebAppData(initData, botToken) {
  if (!initData) return false;
  const urlParams = new URLSearchParams(initData);
  const hash = urlParams.get('hash');
  urlParams.delete('hash');
  
  const dataCheckString = Array.from(urlParams.entries())
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}=${value}`)
    .join('\n');

  const encoder = new TextEncoder();
  const secretKey = await crypto.subtle.importKey(
    "raw", encoder.encode("WebAppData"), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  
  const signature = await crypto.subtle.sign("HMAC", secretKey, encoder.encode(botToken));
  const finalKey = await crypto.subtle.importKey(
    "raw", signature, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  
  const finalSignature = await crypto.subtle.sign("HMAC", finalKey, encoder.encode(dataCheckString));
  
  const hashHex = Array.from(new Uint8Array(finalSignature))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

  return hashHex === hash;
}
