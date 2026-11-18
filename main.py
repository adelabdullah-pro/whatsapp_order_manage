import os
import json
import base64
import hashlib
import hmac
import io
from typing import Optional, List
from fastapi import (
    FastAPI,
    HTTPException,
    status,
    Header,
    Depends,
    Request,
    Response,
    File,
    UploadFile,

)
from pydantic import BaseModel, EmailStr
from supabase import create_client, Client
from dotenv import load_dotenv
import qrcode
from PIL import Image
import httpx
import cv2
from datetime import datetime, timezone
import numpy as np
from difflib import get_close_matches
from openai import AsyncOpenAI


load_dotenv()

app = FastAPI(title="Auth API with Supabase")
# ==================== تخزين جلسات محادثات الواتساب المؤقتة ====================
USER_SESSIONS = {}

# ==================== تهيئة اتصال Supabase ====================

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

# التحقق من متغيرات البيئة قبل إنشاء الاتصالات
if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError(
        "يجب ضبط SUPABASE_URL و SUPABASE_KEY في متغيرات البيئة"
    )

if not SUPABASE_SERVICE_ROLE_KEY:
    raise RuntimeError(
        "يجب ضبط SUPABASE_SERVICE_ROLE_KEY في متغيرات البيئة"
    )

# اتصال التاجر العادي
supabase: Client = create_client(
    SUPABASE_URL,
    SUPABASE_KEY
)

# اتصال الإدارة للعمليات الخلفية
supabase_admin: Client = create_client(
    SUPABASE_URL,
    SUPABASE_SERVICE_ROLE_KEY
)

# ==================== إعدادات WhatsApp API ====================

WHATSAPP_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN")
META_APP_SECRET = os.getenv("META_APP_SECRET")
WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN")
PHONE_NUMBER_ID = os.getenv("PHONE_NUMBER_ID")


# ==================== نماذج البيانات ====================
class LoginSchema(BaseModel):
    email: EmailStr
    password: str


# ==================== مسارات المصادقة ====================

@app.post("/api/login")
async def login(credentials: LoginSchema):
    try:
        response = supabase.auth.sign_in_with_password({
            "email": credentials.email,
            "password": credentials.password
        })

        if not response.session or not response.user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="تعذر إنشاء جلسة تسجيل الدخول"
            )

        return {
            "status": "success",
            "message": "تم تسجيل الدخول بنجاح",
            "access_token": response.session.access_token,
            "user": {
                "id": response.user.id,
                "email": response.user.email
            }
        }

    except HTTPException:
        raise

    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="فشل تسجيل الدخول، تحقق من البريد الإلكتروني وكلمة المرور"
        )


@app.post("/api/register")
async def register_disabled():
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="التسجيل العام غير متاح"
    )


# ==================== التحقق من التوكن ====================
# ==================== التحقق من التوكن (مصحح ومحدث) ====================

async def get_current_user_id(
    authorization: Optional[str] = Header(default=None)
):
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="يجب تسجيل الدخول أولاً",
            headers={"WWW-Authenticate": "Bearer"}
        )

    parts = authorization.strip().split()

    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=401,
            detail="صيغة رمز المصادقة غير صحيحة",
            headers={"WWW-Authenticate": "Bearer"}
        )

    token = parts[1].strip()

    try:
        # استخدام الطريقة المباشرة والآمنة لجلب المستخدم عبر التوكن في Supabase
        user_response = supabase.auth.get_user(token)
        
        # التعامل مع اختلاف هياكل الاستجابة في مكتبة supabase-py
        user_obj = getattr(user_response, 'user', None) or (user_response.get('user') if isinstance(user_response, dict) else None)

        if not user_obj:
            raise HTTPException(
                status_code=401,
                detail="لم يرجع Supabase مستخدمًا صالحًا للتوكن"
            )

        user_id = getattr(user_obj, 'id', None) or (user_obj.get('id') if isinstance(user_obj, dict) else None)
        
        if not user_id:
            raise HTTPException(
                status_code=401,
                detail="تعذر استخلاص معرف المستخدم من التوكن"
            )

        return str(user_id)

    except HTTPException:
        raise

    except Exception as e:
        print("🔥 AUTH VERIFICATION ERROR:", repr(e))
        raise HTTPException(
            status_code=401,
            detail=f"فشل التحقق من التوكن: {str(e)}"
        )

    

@app.get("/api/auth/me")
async def auth_me(
    user_id: str = Depends(get_current_user_id)
):
    return {
        "authenticated": True,
        "user_id": user_id
    }


# ==================== دالة توليد ودمج الباركود على الصورة ====================

async def apply_qr_overlay(image_bytes: bytes, qr_data: str) -> bytes:
    base_image = Image.open(io.BytesIO(image_bytes)).convert("RGBA")
    base_w, base_h = base_image.size

    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=2,
    )

    qr.add_data(qr_data)
    qr.make(fit=True)

    qr_img = qr.make_image(
        fill_color="black",
        back_color="white"
    ).convert("RGBA")

    qr_img = qr_img.resize((100, 100))

    margin = 15
    position_x = base_w - 100 - margin
    position_y = base_h - 100 - margin

    if position_x < 0 or position_y < 0:
        qr_img = qr_img.resize((50, 50))
        position_x = base_w - 50 - margin
        position_y = base_h - 50 - margin

    base_image.paste(qr_img, (position_x, position_y), qr_img)

    output_io = io.BytesIO()
    final_image = base_image.convert("RGB")

    final_image.save(
        output_io,
        format="JPEG",
        quality=95
    )

    output_io.seek(0)

    return output_io.read()


# ==================== جلب المنتجات ====================
@app.get("/api/products")
async def get_products(user_id: str = Depends(get_current_user_id)):
    try:
        # جلب المنتجات التي لم يتم أرشفعتها فقط للتاجر الحالي
        response = (
            supabase_admin.table("products")
            .select("*")
            .eq("owner_id", user_id)
            .neq("status", "archived") # استبعاد المنتجات المؤرشفة منطقياً
            .execute()
        )

        return {
            "status": "success",
            "data": response.data
        }

    except Exception as e:
        print("❌ Error fetching products:", repr(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="تعذر جلب المنتجات"
        )

# ==================== حفظ المنتج مع الصور والألوان ====================
@app.post("/api/products/with-images")
async def add_product_with_images(
    request: Request,
    user_id: str = Depends(get_current_user_id)
):
    try:
        form = await request.form()

        model_number = form.get("model_number")
        name = form.get("name")
        retail_price = float(form.get("retail_price"))

        wholesale_price = (
            float(form.get("wholesale_price"))
            if form.get("wholesale_price")
            and form.get("wholesale_price") != "null"
            else None
        )

        product_status = form.get("status", "draft")
        description = form.get("description")
        colors_json = form.get("colors_json", "[]")

        colors_data = json.loads(colors_json)
        qr_code_value = f"BAR-{model_number.upper()}"

        prod_data = {
            "owner_id": user_id,
            "model_number": model_number,
            "name": name,
            "description": description,
            "retail_price": retail_price,
            "wholesale_price": wholesale_price,
            "status": product_status,
        }

        prod_res = (
            supabase.table("products")
            .insert(prod_data)
            .execute()
        )

        if not prod_res.data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="فشل إنشاء المنتج الأساسي في قاعدة البيانات"
            )

        product_id = prod_res.data[0]["id"]

        general_images = form.getlist("general_images")

        for img in general_images:
            if hasattr(img, "filename") and img.filename:
                image_bytes = await img.read()

                processed_bytes = await apply_qr_overlay(
                    image_bytes,
                    qr_code_value
                )

                file_name = (
                    f"gen_{os.urandom(4).hex()}_{os.path.basename(img.filename)}"
                )

                file_path = (
                    f"products/{product_id}/general/{file_name}"
                )

                supabase.storage.from_("product-images").upload(
                    file_path,
                    processed_bytes,
                    file_options={"content-type": "image/jpeg"}
                )

                public_url = (
                    supabase.storage
                    .from_("product-images")
                    .get_public_url(file_path)
                )

                supabase.table("product_images").insert({
                    "product_id": product_id,
                    "image_url": public_url,
                    "image_type": "general"
                }).execute()

        for index, color_item in enumerate(colors_data):
            color_name = color_item.get("color_name")

            if not color_name or not str(color_name).strip():
                continue

            # تجهيز بيانات اللون بشكل آمن لتجنب إرسال قيم null تسبب انهيار القاعدة
            color_insert_data = {
                "product_id": product_id,
                "color_name": str(color_name).strip(),
            }
            if color_item.get("color_code"):
                color_insert_data["color_code"] = color_item.get("color_code")

            color_res = supabase.table("product_colors").insert(color_insert_data).execute()

            if color_res.data:
                color_id = color_res.data[0]["id"]

                for variant in color_item.get("variants", []):
                    size_label = variant.get("size_label")

                    if size_label and str(size_label).strip():
                        supabase.table("product_variants").insert({
                            "color_id": color_id,
                            "size_label": str(size_label).strip(),
                            "stock_qty": variant.get("stock_qty", 0)
                        }).execute()

                color_images = form.getlist(f"color_images_{index}")

                for img in color_images:
                    if hasattr(img, "filename") and img.filename:
                        image_bytes = await img.read()

                        processed_bytes = await apply_qr_overlay(
                            image_bytes,
                            qr_code_value
                        )

                        file_name = (
                            f"col_{os.urandom(4).hex()}_{os.path.basename(img.filename)}"
                        )

                        file_path = (
                            f"products/{product_id}/colors/{color_id}/{file_name}"
                        )

                        supabase.storage.from_("product-images").upload(
                            file_path,
                            processed_bytes,
                            file_options={"content-type": "image/jpeg"}
                        )

                        public_url = (
                            supabase.storage
                            .from_("product-images")
                            .get_public_url(file_path)
                        )

                        supabase.table("product_images").insert({
                            "product_id": product_id,
                            "color_id": color_id,
                            "image_url": public_url,
                            "image_type": "color"
                        }).execute()

        return {
            "status": "success",
            "message": "تم حفظ المنتج والألوان والمقاسات والصور ودمج الباركود بنجاح",
            "product_id": product_id,
            "data": prod_res.data[0]
        }

    except HTTPException:
        raise

    except Exception as e:
        # 🔍 طباعة الخطأ البرمجي الحقيقي بالكامل في لوحة تحكم Render Logs
        print("🔥 DETAILED ADD PRODUCT ERROR:", repr(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"خطأ أثناء حفظ المنتج: {str(e)}"
        )
# ==================== جلب صور المنتجات ====================

# ==================== جلب صور المنتجات ====================

@app.get("/api/product-images")
async def get_product_images(
    user_id: str = Depends(get_current_user_id)
):
    try:
        # جلب منتجات التاجر الحالي فقط
        products_response = (
            supabase_admin.table("products")
            .select("id")
            .eq("owner_id", user_id)
            .execute()
        )

        product_ids = [
            product["id"]
            for product in (products_response.data or [])
        ]

        # إذا لم تكن لديه منتجات، نعيد قائمة صور فارغة
        if not product_ids:
            return {
                "status": "success",
                "data": []
            }

        # جلب صور منتجات التاجر الحالي فقط
        response = (
            supabase_admin.table("product_images")
            .select("*")
            .in_("product_id", product_ids)
            .execute()
        )

        return {
            "status": "success",
            "data": response.data
        }

    except Exception as e:
        print("❌ Error fetching product images:", repr(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="تعذر جلب صور المنتجات"
        )

# ==================== دالة إرسال رسائل واتساب ====================
async def send_whatsapp_message(to_phone: str, text: str):
    if not WHATSAPP_TOKEN or not PHONE_NUMBER_ID:
        print("❌ خطأ: WHATSAPP_TOKEN أو PHONE_NUMBER_ID غير معرفات في البيئة!")
        return False

    url = f"https://graph.facebook.com/v19.0/{PHONE_NUMBER_ID}/messages"
    headers = {
        "Authorization": f"Bearer {WHATSAPP_TOKEN}",
        "Content-Type": "application/json",
    }
    payload = {
        "messaging_product": "whatsapp",
        "to": to_phone,
        "type": "text",
        "text": {"body": text},
    }

    async with httpx.AsyncClient() as client:
        try:
            res = await client.post(url, json=payload, headers=headers)
            print(f"🔍 WhatsApp API Status Code: {res.status_code}")
            print(f"🔍 WhatsApp API Response Body: {res.text}") # <--- هذا السطر سيكشف السر فوراً
            return res.status_code == 200
        except Exception as e:
            print("❌ Exception in send_whatsapp_message:", repr(e))
            return False
# ==================== WhatsApp Webhook Routes ====================

@app.get("/webhook")
async def verify_whatsapp_webhook(request: Request):
    mode = request.query_params.get("hub.mode")
    token = request.query_params.get("hub.verify_token")
    challenge = request.query_params.get("hub.challenge")

    if not WHATSAPP_VERIFY_TOKEN:
        raise HTTPException(
            status_code=503,
            detail="Webhook verification is not configured",
        )
    if not mode or token is None or challenge is None:
        raise HTTPException(status_code=400, detail="Invalid request")
    if mode == "subscribe" and hmac.compare_digest(token, WHATSAPP_VERIFY_TOKEN):
        return Response(content=challenge, media_type="text/plain")
    raise HTTPException(status_code=403, detail="Verification token mismatch")


def verify_meta_signature(raw_body: bytes, signature: Optional[str]) -> None:
    if not META_APP_SECRET:
        raise HTTPException(
            status_code=503,
            detail="Webhook signature verification is not configured",
        )
    if not signature:
        raise HTTPException(status_code=401, detail="Missing webhook signature")

    expected_signature = "sha256=" + hmac.new(
        META_APP_SECRET.encode("utf-8"),
        raw_body,
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected_signature, signature):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")


# ==================== دالة استقبال رسائل واتساب (مصححة ومنظمة) ====================
@app.post("/webhook")
async def receive_whatsapp_message(request: Request):
    raw_body = await request.body()
    verify_meta_signature(
        raw_body,
        request.headers.get("X-Hub-Signature-256"),
    )

    try:
        body = json.loads(raw_body)

        entry = body.get("entry", [])
        for ent in entry:
            changes = ent.get("changes", [])
            for change in changes:
                value = change.get("value", {})
                messages = value.get("messages")
                if not messages:
                    continue

                msg = messages[0]
                sender_phone = msg.get("from")
                msg_type = msg.get("type")

                if not sender_phone:
                    continue

                # جلب حالة الجلسة الحالية للعميل
                session = USER_SESSIONS.get(sender_phone, {"step": "IDLE"})

                # ----------------------------------------------------
                # الحالة الأولى: إذا أرسل العميل صورة (باركود) - نعالجها فوراً في أي وقت
                # ----------------------------------------------------
                if msg_type == "image":
                    image_data = msg.get("image", {})
                    media_id = image_data.get("id")

                    barcode_value = await download_and_decode_whatsapp_image(media_id)

                    if not barcode_value:
                        reply_text = (
                            "❌ عذراً، لم نتمكن من قراءة الباركود بوضوح من الصورة.\n"
                            "الرجاء إرسال صورة واضحة تحتوي على باركود المحل لاستكمال الطلب 🌸"
                        )
                        await send_whatsapp_message(sender_phone, reply_text)
                        continue

                    model_number = barcode_value.replace("BAR-", "").strip()

                    # فحص المنتج وجلب بياناته من قاعدة البيانات
                    db_res = (
                        supabase_admin.table("products")
                        .select("*, product_colors(id, color_name, product_variants(id, size_label, stock_qty))")
                        .ilike("model_number", model_number)
                        .execute()
                    )

                    if not db_res.data or len(db_res.data) == 0:
                        await send_whatsapp_message(sender_phone, f"❌ الباركود ({barcode_value}) غير مسجل في نظامنا.")
                        continue

                    product = db_res.data[0]

                    # التحقق من اسم العميل المسبق في قاعدة البيانات
                    existing_customer_res = (
                        supabase_admin.table("orders")
                        .select("customer_name")
                        .eq("customer_phone", sender_phone)
                        .not_.eq("customer_name", "عميل واتساب")
                        .limit(1)
                        .execute()
                    )

                    known_customer_name = None
                    if existing_customer_res.data and len(existing_customer_res.data) > 0:
                        known_customer_name = existing_customer_res.data[0].get("customer_name")

                    # تصفية الألوان التي تحتوي على مخزون فعلي فقط (> 0)
                    all_colors = product.get("product_colors", [])
                    valid_colors = []
                    for c in all_colors:
                        has_stock = any(v.get("stock_qty", 0) > 0 for v in c.get("product_variants", []))
                        if has_stock:
                            valid_colors.append(c)

                    # 🚨 التحقق الذكي: إذا كان المنتج نفد بالكامل من المخزون
                    if len(valid_colors) == 0:
                        customer_title = f"يا *{known_customer_name}*" if known_customer_name else "عزيزنا العميل"
                        out_of_stock_msg = (
                            f"أهلاً بك {customer_title} 🌸\n"
                            f"يسعدنا جداً اهتمامك بـ (*{product['name']}*) في **فالنسيا**! ✨\n\n"
                            f"نود إبلاغك بأن هذا المنتج قد **نفد بالكامل حالياً** نظراً للإقبال اللطيف عليه 💎\n\n"
                            f"نعمل باستمرار على إعادة توفير تشكيلاتنا المميزة، ويمكنك إرسال صورة لمنتج آخر وسنكون سعداء جداً بخدمتك 🌺"
                        )
                        USER_SESSIONS.pop(sender_phone, None) # تصفير الجلسة تماماً
                        await send_whatsapp_message(sender_phone, out_of_stock_msg)
                        continue

                    session_data = {
                        "product_id": product["id"],
                        "product_name": product["name"],
                        "model_number": model_number,
                        "retail_price": product["retail_price"],
                        "colors_data": valid_colors
                    }

                    if known_customer_name:
                        session_data["customer_name"] = known_customer_name
                    else:
                        session_data["customer_name"] = None

                    greeting = f"أهلاً بك مرة أخرى يا *{known_customer_name}*! 🌸" if known_customer_name else f"أهلاً بك في محل فالنسيا! 🌸\nالمنتج (*{product['name']}*) متوفر لدينا بسعر {product['retail_price']} ريال.\n\nلخدمتك بشكل أفضل، يرجى إرسال **اسمك الكريم** أولاً:"

                    # إذا لم يتبقى إلا لون واحد متاح للمنتج
                    if len(valid_colors) == 1:
                        single_color = valid_colors[0]
                        session_data["pending_color"] = single_color
                        if known_customer_name:
                            session_data["step"] = "CONFIRM_SINGLE_COLOR"
                            reply_text = (
                                f"{greeting}\n"
                                f"✅ المنتج: {product['name']}\n"
                                f"🎨 اللون المتاح الوحيد هو: *{single_color['color_name']}*.\n"
                                f"هل تريد هذا اللون؟ (اكتب **نعم** أو **لا**):"
                            )
                        else:
                            session_data["step"] = "AWAITING_NAME"
                            reply_text = f"{greeting}"
                    else:
                        if known_customer_name:
                            session_data["step"] = "AWAITING_COLOR"
                            colors_list_str = "".join([f"- {c['color_name']}\n" for c in valid_colors])
                            reply_text = (
                                f"{greeting}\n"
                                f"✅ **المنتج متوفر:** {product['name']}\n"
                                f"💰 السعر: {product['retail_price']} ريال\n\n"
                                f"🎨 **الألوان المتوفرة:**\n{colors_list_str}\n"
                                f"يرجى إرسال **اسم اللون** المطلوب الآن:"
                            )
                        else:
                            session_data["step"] = "AWAITING_NAME"
                            reply_text = f"{greeting}"

                    USER_SESSIONS[sender_phone] = session_data
                    await send_whatsapp_message(sender_phone, reply_text)
                    continue

                # ----------------------------------------------------
                # الحالة الثانية: إذا أرسل العميل رسالة نصية
                # ----------------------------------------------------
                elif msg_type == "text":
                    incoming_text = msg.get("text", {}).get("body", "").strip()
                    
                    # معالجة أمر الإلغاء/التصفير العام في أي وقت
                    if incoming_text in ["إلغاء", "الغاء", "cancel", "reset", "البداية"]:
                        USER_SESSIONS.pop(sender_phone, None)
                        await send_whatsapp_message(
                            sender_phone, 
                            "🔄 تم إلغاء العملية الحالية وتصفير المحادثة.\nأرسل صورة جديدة للمنتج متى ما أردت البدء من جديد 🌸"
                        )
                        continue

                    current_step = session.get("step", "IDLE")

                    if current_step == "IDLE":
                        default_reply = (
                            "مرحباً بك في محل فالنسيا! 🌸\n"
                            "لبدء الطلب، يرجى إرسال صورة المنتج مع الباركود الخاص به."
                        )
                        await send_whatsapp_message(sender_phone, default_reply)
                        continue

                    # الخطوة 0: استقبال اسم العميل (للعميل الجديد) وحفظه
                    if current_step == "AWAITING_NAME":
                        customer_name = incoming_text
                        session["customer_name"] = customer_name
                        valid_colors = session.get("colors_data", [])

                        if len(valid_colors) == 1:
                            single_color = valid_colors[0]
                            session["pending_color"] = single_color
                            session["step"] = "CONFIRM_SINGLE_COLOR"
                            reply_text = (
                                f"يسعدنا تعارفنا معك يا *{customer_name}*! ✨\n"
                                f"🎨 اللون المتاح الوحيد هو: *{single_color['color_name']}*.\n"
                                f"هل تريد هذا اللون؟ (اكتب **نعم** أو **لا**):"
                            )
                        else:
                            session["step"] = "AWAITING_COLOR"
                            colors_list_str = "".join([f"- {c['color_name']}\n" for c in valid_colors])
                            reply_text = (
                                f"يسعدنا تعارفنا معك يا *{customer_name}*! ✨\n\n"
                                f"🎨 **الألوان المتوفرة للمنتج:**\n{colors_list_str}\n"
                                f"يرجى إرسال **اسم اللون** المطلوب الآن:"
                            )
                        USER_SESSIONS[sender_phone] = session
                        await send_whatsapp_message(sender_phone, reply_text)
                        continue

                    # تأكيد اللون الوحيد (نعم / لا)
                    elif current_step == "CONFIRM_SINGLE_COLOR":
                        if incoming_text.lower() in ["نعم", "ايوه", "يس", "yes", "y"]:
                            matched_color = session.get("pending_color")
                            session["selected_color"] = matched_color["color_name"]
                            session["selected_color_id"] = matched_color["id"]
                            
                            valid_variants = [v for v in matched_color.get("product_variants", []) if v.get("stock_qty", 0) > 0]
                            if len(valid_variants) == 1:
                                single_variant = valid_variants[0]
                                session["pending_variant"] = single_variant
                                session["step"] = "CONFIRM_SINGLE_SIZE"
                                reply_text = (
                                    f"تم اعتماد اللون: *{matched_color['color_name']}* 👍\n"
                                    f"📏 المقاس المتاح الوحيد هو: *{single_variant['size_label']}* (المتوفر: {single_variant['stock_qty']} قطعه).\n"
                                    f"هل تريد هذا المقاس؟ (اكتب **نعم** أو **لا**):"
                                )
                            else:
                                session["step"] = "AWAITING_SIZE"
                                sizes_str = "".join([f"- المقاس: {v['size_label']} (المتوفر: {v['stock_qty']} قطعه)\n" for v in valid_variants])
                                reply_text = (
                                    f"تم اعتماد اللون: *{matched_color['color_name']}* 👍\n\n"
                                    f"📏 **المقاسات المتاحة:**\n{sizes_str}\n"
                                    f"الرجاء إرسال **المقاس** المطلوب:"
                                )
                        else:
                            USER_SESSIONS.pop(sender_phone, None)
                            reply_text = "🔄 تم إلغاء الطلب. أرسل صورة جديدة متى شئت."
                        
                        USER_SESSIONS[sender_phone] = session
                        await send_whatsapp_message(sender_phone, reply_text)
                        continue

                    # الخطوة أ: اختيار اللون مع التصحيح الإملائي
                    elif current_step == "AWAITING_COLOR":
                        colors_data = session.get("colors_data", [])
                        valid_color_names = [c["color_name"] for c in colors_data]
                        
                        matched_name = None
                        close_matches = get_close_matches(incoming_text.lower(), [name.lower() for name in valid_color_names], n=1, cutoff=0.5)
                        if close_matches:
                            matched_name = next(c for c in valid_color_names if c.lower() == close_matches[0])

                        matched_color = next((c for c in colors_data if c["color_name"] == matched_name), None)

                        if not matched_color:
                            await send_whatsapp_message(sender_phone, "❌ اللون الذي أدخلته غير متوفر أو غير واضح. يرجى اختيار لون صحيح من القائمة:")
                            continue

                        session["selected_color"] = matched_color["color_name"]
                        session["selected_color_id"] = matched_color["id"]
                        
                        valid_variants = [v for v in matched_color.get("product_variants", []) if v.get("stock_qty", 0) > 0]
                        
                        if len(valid_variants) == 1:
                            single_variant = valid_variants[0]
                            session["pending_variant"] = single_variant
                            session["step"] = "CONFIRM_SINGLE_SIZE"
                            reply_text = (
                                f"تم اختيار اللون: *{matched_color['color_name']}* 🌸\n"
                                f"📏 المقاس المتاح الوحيد لهذا اللون هو: *{single_variant['size_label']}* (المتوفر: {single_variant['stock_qty']} قطعه).\n"
                                f"هل تريد هذا المقاس؟ (اكتب **نعم** أو **لا**):"
                            )
                        else:
                            session["step"] = "AWAITING_SIZE"
                            sizes_str = "".join([f"- المقاس: {v['size_label']} (المتوفر: {v['stock_qty']} قطعه)\n" for v in valid_variants])
                            reply_text = (
                                f"تم اختيار اللون: *{matched_color['color_name']}* 🌸\n\n"
                                f"📏 **المقاسات المتاحة:**\n{sizes_str}\n"
                                f"الرجاء إرسال **المقاس** المطلوب:"
                            )
                        
                        USER_SESSIONS[sender_phone] = session
                        await send_whatsapp_message(sender_phone, reply_text)
                        continue

                    # تأكيد المقاس الوحيد (نعم / لا)
                    elif current_step == "CONFIRM_SINGLE_SIZE":
                        if incoming_text.lower() in ["نعم", "ايوه", "يس", "yes", "y"]:
                            matched_variant = session.get("pending_variant")
                            session["selected_size"] = matched_variant["size_label"]
                            session["max_stock"] = matched_variant["stock_qty"]
                            session["step"] = "AWAITING_QUANTITY"
                            
                            reply_text = (
                                f"تم اعتماد المقاس: *{matched_variant['size_label']}* 👍\n"
                                f"المخزون المتاح: {matched_variant['stock_qty']} قطعة.\n"
                                f"كم عدد القطع أو **الكمية** المطلوبة؟ (اكتب رقم الكمية):"
                            )
                        else:
                            USER_SESSIONS.pop(sender_phone, None)
                            reply_text = "🔄 تم إلغاء الطلب. أرسل صورة جديدة متى شئت."
                        
                        USER_SESSIONS[sender_phone] = session
                        await send_whatsapp_message(sender_phone, reply_text)
                        continue

                    # الخطوة ب: اختيار المقاس مع المطابقة الذكية
                    elif current_step == "AWAITING_SIZE":
                        colors_data = session.get("colors_data", [])
                        selected_color_id = session.get("selected_color_id")
                        target_color = next((c for c in colors_data if c["id"] == selected_color_id), None)
                        
                        matched_variant = None
                        if target_color:
                            valid_variants = [v for v in target_color.get("product_variants", []) if v.get("stock_qty", 0) > 0]
                            valid_sizes_str = [str(v["size_label"]) for v in valid_variants]
                            
                            close_size_matches = get_close_matches(incoming_text.lower(), [s.lower() for s in valid_sizes_str], n=1, cutoff=0.5)
                            matched_size_label = close_size_matches[0] if close_size_matches else None
                            
                            matched_variant = next((v for v in valid_variants if str(v["size_label"]).lower() == matched_size_label), None)

                        if not matched_variant:
                            await send_whatsapp_message(sender_phone, "❌ المقاس المدخل غير صحيح أو نفذ من المخزون. يرجى اختيار مقاس من القائمة:")
                            continue

                        session["selected_size"] = matched_variant["size_label"]
                        session["max_stock"] = matched_variant["stock_qty"]
                        session["step"] = "AWAITING_QUANTITY"
                        USER_SESSIONS[sender_phone] = session

                        reply_text = f"تم اختيار المقاس: *{matched_variant['size_label']}* 👍\nالمخزون المتاح: {matched_variant['stock_qty']} قطعة.\nكم عدد القطع المطلوبة؟ (اكتب رقم الكمية):"
                        await send_whatsapp_message(sender_phone, reply_text)
                        continue

                    # الخطوة ج: الكمية
                    elif current_step == "AWAITING_QUANTITY":
                        try:
                            qty = int(incoming_text)
                        except ValueError:
                            qty = 1

                        max_stock = session.get("max_stock", 1)
                        if qty > max_stock:
                            await send_whatsapp_message(sender_phone, f"⚠️ عذراً، الكمية المطلوبة أكبر من المخزون المتوفر ({max_stock} قطعة). يرجى كتابة كمية أقل:")
                            continue
                        if qty <= 0:
                            qty = 1

                        session["quantity"] = qty
                        session["step"] = "AWAITING_ADDRESS"
                        USER_SESSIONS[sender_phone] = session

                        reply_text = "رائع! 📦\nالرجاء إرسال **عنوان الشحن الخاص بك** بالتفصيل لتسجيل الطلب فوراً:"
                        await send_whatsapp_message(sender_phone, reply_text)
                        continue

                    # الخطوة د: العنوان وحفظ الطلب وخصم المخزون
                    elif current_step == "AWAITING_ADDRESS":
                        shipping_address = incoming_text
                        
                        profile_res = (
                            supabase_admin.table("profiles")
                            .select("id")
                            .limit(1)
                            .execute()
                        )

                        if not profile_res.data:
                            await send_whatsapp_message(sender_phone, "❌ عذراً، حدث خطأ في النظام. يرجى المحاولة لاحقاً.")
                            return {"status": "error"}

                        owner_id = profile_res.data[0]["id"]
                        unit_price = session.get("retail_price", 0)
                        quantity = session.get("quantity", 1)
                        total_amount = unit_price * quantity
                        
                        customer_name = session.get("customer_name", "عميل واتساب")

                        order_payload = {
                            "owner_id": owner_id,
                            "customer_name": customer_name,
                            "customer_phone": sender_phone,
                            "source": "whatsapp",
                            "status": "new",
                            "payment_status": "unpaid",
                            "subtotal": total_amount,
                            "delivery_fee": 0.00,
                            "discount": 0.00,
                            "total": total_amount,
                            "currency": "YER",
                            "shipping_address": shipping_address,
                            "customer_notes": "طلب عبر محادثة واتساب التلقائية"
                        }

                        order_res = supabase_admin.table("orders").insert(order_payload).execute()

                        if order_res.data:
                            new_order = order_res.data[0]
                            order_id = new_order["id"]

                            product_id = session.get("product_id")
                            selected_color_id = session.get("selected_color_id")
                            selected_size = session.get("selected_size")

                            item_payload = {
                                "order_id": order_id,
                                "product_id": product_id,
                                "product_name": session.get("product_name"),
                                "model_number": session.get("model_number"),
                                "color_name": session.get("selected_color"),
                                "size_label": selected_size,
                                "unit_price": unit_price,
                                "quantity": quantity,
                                "line_total": total_amount
                            }

                            supabase_admin.table("order_items").insert(item_payload).execute()

                            variant_res = (
                                supabase_admin.table("product_variants")
                                .select("id, stock_qty")
                                .eq("color_id", selected_color_id)
                                .eq("size_label", selected_size)
                                .execute()
                            )

                            if variant_res.data and len(variant_res.data) > 0:
                                variant_record = variant_res.data[0]
                                current_stock = variant_record.get("stock_qty", 0)
                                new_stock = max(0, current_stock - quantity)

                                supabase_admin.table("product_variants")\
                                    .update({"stock_qty": new_stock})\
                                    .eq("id", variant_record["id"])\
                                    .execute()

                            USER_SESSIONS.pop(sender_phone, None)

                            confirm_reply = (
                                f"🎉 **تم تسجيل طلبك بنجاح يا {customer_name}!**\n"
                                f"📦 رقم الطلب التعريفي: `{order_id[:8]}`\n"
                                f"📍 عنوان الشحن: {shipping_address}\n\n"
                                f"سيقوم فريق فالنسيا بتجهيز طلبك والتواصل معك قريباً. شكراً لك! 🌸"
                            )
                            await send_whatsapp_message(sender_phone, confirm_reply)
                        else:
                            await send_whatsapp_message(sender_phone, "❌ فشل في حفظ الطلب في قاعدة البيانات. يرجى إعادة المحاولة.")
                        continue

        return {"status": "EVENT_RECEIVED"}

    except Exception as e:
        print("❌ CRITICAL WEBHOOK ERROR:", repr(e))
        return {"status": "error", "details": str(e)}

# ==================== دالة تحميل وقراءة الباركود مع القص الذكي للزاوية ====================
async def download_and_decode_whatsapp_image(media_id: str) -> Optional[str]:
    try:
        media_url_endpoint = f"https://graph.facebook.com/v19.0/{media_id}"
        headers = {"Authorization": f"Bearer {WHATSAPP_TOKEN}"}
        
        async with httpx.AsyncClient() as client:
            res = await client.get(media_url_endpoint, headers=headers)
            if res.status_code != 200:
                return None
            
            media_data = res.json()
            image_download_url = media_data.get("url")
            if not image_download_url:
                return None

            img_res = await client.get(image_download_url, headers=headers)
            if img_res.status_code != 200:
                return None

            image_bytes = img_res.content
            nparr = np.frombuffer(image_bytes, np.uint8)
            img_cv = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

            if img_cv is None:
                return None

            detector = cv2.QRCodeDetector()

            # 1️⃣ المحاولة الأولى: فحص الصورة الكاملة مباشرة
            val, _, _ = detector.detectAndDecode(img_cv)
            if val and val.strip():
                print(f"✅ تم العثور على باركود من الصورة الكاملة: {val}")
                return val.strip()

            # 2️⃣ المحاولة الثانية: قص زاوية أسفل اليمين (حيث يتواجد الباركود عادة)
            h, w, _ = img_cv.shape
            # تحديد المنطقة السفلى اليمنى (آخر 35% من الارتفاع و 35% من العرض)
            crop_y1 = int(h * 0.65)
            crop_x1 = int(w * 0.65)
            bottom_right_crop = img_cv[crop_y1:h, crop_x1:w]

            # تجربة قراءة الزاوية المقصوصة مباشرة
            val_crop, _, _ = detector.detectAndDecode(bottom_right_crop)
            if val_crop and val_crop.strip():
                print(f"✅ تم العثور على باركود بعد قص الزاوية السفلى: {val_crop}")
                return val_crop.strip()

            # 3️⃣ المحاولة الثالثة: تكبير الزاوية المقصوصة وتعديل التباين (CLAHE)
            resized_crop = cv2.resize(bottom_right_crop, (0, 0), fx=2.0, fy=2.0, interpolation=cv2.INTER_CUBIC)
            gray_crop = cv2.cvtColor(resized_crop, cv2.COLOR_BGR2GRAY)
            clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8))
            enhanced_crop = clahe.apply(gray_crop)

            val_enhanced, _, _ = detector.detectAndDecode(enhanced_crop)
            if val_enhanced and val_enhanced.strip():
                print(f"✅ تم العثور على باركود بعد قص وتكبير وتحسين الزاوية: {val_enhanced}")
                return val_enhanced.strip()

            print("⚠️ لم يتم العثور على باركود في الصورة أو في الزاوية المقصوصة")
            return None

    except Exception as e:
        print("❌ خطأ أثناء قراءة الباركود:", repr(e))
        return None


# ==================== ادارة الطلبات ====================

# نماذج البيانات (Pydantic Models) للتحقق من المدخلات
class OrderStatusUpdate(BaseModel):
    new_status: str  # مثال: new, processing, shipping, completed, cancelled
    cancellation_reason: Optional[str] = None
    notes: Optional[str] = None

# 1. جلب قائمة الطلبات مع إمكانية التصفية والبحث
@app.get("/api/orders")
async def get_orders(
    status: Optional[str] = None, 
    search: Optional[str] = None, 
    limit: int = 50,
    user_id: str = Depends(get_current_user_id)
):
    orders = []
    
    try:
        print(f"📦 جلب الطلبات للمستخدم برقم ID: {user_id}")
        
        # 🎯 قم بكتابة واستخدام السطر هنا بدلاً من الاستعلام القديم:
        response = (
            supabase_admin.table("orders")
            .select("*, order_items(*)")
            .eq("owner_id", user_id)
            .order("created_at", desc=True)
            .limit(limit)
        )
        
        if status and status != 'all':
            response = response.eq("status", status)
            
        query_res = response.execute()
        orders = query_res.data or []
        
        print(f"✅ عدد الطلبات التي تم العثور عليها في قاعدة البيانات: {len(orders)}")
        
        if search:
            search_lower = search.lower()
            orders = [
                o for o in orders 
                if search_lower in str(o.get("order_number", "")).lower() 
                or search_lower in o.get("customer_name", "").lower() 
                or search_lower in o.get("customer_phone", "")
            ]
            
        return {"status": "success", "count": len(orders), "data": orders}
        
    except Exception as e:
        print("❌ Error fetching orders:", repr(e))
        raise HTTPException(status_code=500, detail=str(e))
    
# 2. 🚀 إضافة المسار المفقود لجلب تفاصيل طلب معين (مطلوب لـ OrderDetailsScreen)
@app.get("/api/orders/{order_id}")
async def get_order_details(
    order_id: str,
    user_id: str = Depends(get_current_user_id)
):
    try:
        # استخدام supabase_admin لتجاوز RLS
        order_res = (
            supabase_admin.table("orders")
            .select("*")
            .eq("id", order_id)
            .eq("owner_id", user_id)
            .execute()
        )
        
        if not order_res.data:
            raise HTTPException(status_code=404, detail="الطلب غير موجود")
            
        order_data = order_res.data[0]
        
        items_res = (
            supabase_admin.table("order_items")
            .select("*")
            .eq("order_id", order_id)
            .execute()
        )
        
        logs_res = (
            supabase_admin.table("order_logs")
            .select("*")
            .eq("order_id", order_id)
            .order("created_at", desc=True)
            .execute()
        )
        
        return {
            "order": order_data,
            "items": items_res.data or [],
            "logs": logs_res.data or []
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print("❌ Error fetching order details:", repr(e))
        raise HTTPException(status_code=500, detail=str(e))

    
# 3. تحديث حالة الطلب وتسجيل الحركة مع إدارة المخزون باتجاهين (الإلغاء والإعادة)
@app.put("/api/orders/{order_id}/status")
async def update_order_status(
    order_id: str,
    data: OrderStatusUpdate,
    user_id: str = Depends(get_current_user_id)
):
    try:
        current_order = (
    supabase_admin.table("orders")
    .select("status")
    .eq("id", order_id)
    .eq("owner_id", user_id)
    .execute()
)
        if not current_order.data:
            raise HTTPException(status_code=404, detail="الطلب غير موجود")
            
        old_status = current_order.data[0]["status"]
        new_status = data.new_status
        
        current_time_iso = datetime.now(timezone.utc).isoformat()
        
        update_data = {
            "status": new_status, 
            "updated_at": current_time_iso
        }        
        
        if new_status == "processing":
            update_data["confirmed_at"] = current_time_iso
        elif new_status == "shipping":
            update_data["shipped_at"] = current_time_iso
        elif new_status == "completed":
            update_data["delivered_at"] = current_time_iso
        elif new_status == "cancelled":
            update_data["cancelled_at"] = current_time_iso
            if data.cancellation_reason:
                update_data["cancellation_reason"] = data.cancellation_reason

        # 🔄 إدارة المخزون التلقائية بناءً على تغير الحالة:
        
        # الحالة الأولى: التحول إلى "ملغي" من حالة نشطة (إعادة الكمية للمخزون)
        if old_status != "cancelled" and new_status == "cancelled":
            items_res = supabase_admin.table("order_items").select("*").eq("order_id", order_id).execute()
            for item in (items_res.data or []):
                product_id = item.get("product_id")
                color_name = item.get("color_name")
                size_label = item.get("size_label")
                quantity = item.get("quantity", 0)
                
                if product_id and color_name and size_label and quantity > 0:
                    color_res = supabase_admin.table("product_colors").select("id").eq("product_id", product_id).eq("color_name", color_name).execute()
                    if color_res.data:
                        color_id = color_res.data[0]["id"]
                        variant_res = supabase_admin.table("product_variants").select("id, stock_qty").eq("color_id", color_id).eq("size_label", size_label).execute()
                        if variant_res.data:
                            v_rec = variant_res.data[0]
                            new_stock = v_rec.get("stock_qty", 0) + quantity  # إرجاع الكمية
                            supabase_admin.table("product_variants").update({"stock_qty": new_stock}).eq("id", v_rec["id"]).execute()

        # الحالة الثانية: التحول من "ملغي" إلى أي حالة أخرى نشطة (خصم الكمية من المخزون مرة أخرى)
        elif old_status == "cancelled" and new_status != "cancelled":
            items_res = supabase_admin.table("order_items").select("*").eq("order_id", order_id).execute()
            for item in (items_res.data or []):
                product_id = item.get("product_id")
                color_name = item.get("color_name")
                size_label = item.get("size_label")
                quantity = item.get("quantity", 0)
                
                if product_id and color_name and size_label and quantity > 0:
                    color_res = supabase_admin.table("product_colors").select("id").eq("product_id", product_id).eq("color_name", color_name).execute()
                    if color_res.data:
                        color_id = color_res.data[0]["id"]
                        variant_res = supabase_admin.table("product_variants").select("id, stock_qty").eq("color_id", color_id).eq("size_label", size_label).execute()
                        if variant_res.data:
                            v_rec = variant_res.data[0]
                            current_stock = v_rec.get("stock_qty", 0)
                            new_stock = max(0, current_stock - quantity)  # خصم الكمية مجدداً
                            supabase_admin.table("product_variants").update({"stock_qty": new_stock}).eq("id", v_rec["id"]).execute()

        # تنفيذ التحديث في جدول orders
        supabase_admin.table("orders").update(update_data).eq("id", order_id).eq("owner_id", user_id).execute()
        
        # تسجيل الحركة في السجل
        supabase_admin.table("order_logs").insert({
            "order_id": order_id,
            "old_status": old_status,
            "new_status": new_status,
            "notes": data.notes or f"تم تغيير الحالة من {old_status} إلى {new_status}"
        }).execute()

        return {
            "status": "success",
            "message": f"تم تحديث حالة الطلب إلى ({new_status}) بنجاح وتحديث المخزون تلقائياً",
            "old_status": old_status,
            "new_status": new_status
        }
    except Exception as e:
        print("❌ Error updating order status:", repr(e))
        raise HTTPException(status_code=500, detail=f"خطأ في تحديث حالة الطلب: {str(e)}")

# ==================== نموذج بيانات إنشاء طلب جديد (البيع الفوري والطلبات) ====================
class OrderItemSchema(BaseModel):
    product_id: str
    product_name: str
    model_number: Optional[str] = None
    color_name: Optional[str] = None
    size_label: Optional[str] = None
    unit_price: float
    quantity: int

class CreateOrderSchema(BaseModel):
    id: Optional[str] = None
    customer_name: str
    customer_phone: Optional[str] = "غير متاح"
    shipping_address: Optional[str] = "مبيع مباشر من المعرض"
    total: float
    subtotal: Optional[float] = None
    discount: Optional[float] = 0.0
    payment_type: Optional[str] = "cash"
    order_items: List[OrderItemSchema]
    status: Optional[str] = "completed"

# ==================== مسار إنشاء طلب جديد (للبيع الفوري POS) ====================
@app.post("/api/orders")
async def create_order(
    order_data: CreateOrderSchema,
    user_id: str = Depends(get_current_user_id)
):
    try:
        # 1. إدخال الطلب الأساسي في جدول orders
        order_payload = {
            "owner_id": user_id,
            "customer_name": order_data.customer_name,
            "customer_phone": order_data.customer_phone,
            "source": "pos", # أو direct
            "status": order_data.status,
            "payment_status": "paid" if order_data.status == "completed" else "unpaid",
            "subtotal": order_data.subtotal or order_data.total,
            "delivery_fee": 0.00,
            "discount": order_data.discount or 0.00,
            "total": order_data.total,
            "currency": "YER",
            "shipping_address": order_data.shipping_address,
            "customer_notes": f"عملية بيع فوري (POS) - طريقة الدفع: {order_data.payment_type}"
        }

        order_res = supabase_admin.table("orders").insert(order_payload).execute()

        if not order_res.data:
            raise HTTPException(status_code=400, detail="فشل حفظ الطلب في قاعدة البيانات")

        new_order = order_res.data[0]
        order_id = new_order["id"]

        # 2. إدخال عناصر الطلب في table order_items وخصم المخزون من product_variants
        for item in order_data.order_items:
            line_total = item.unit_price * item.quantity
            item_payload = {
                "order_id": order_id,
                "product_id": item.product_id,
                "product_name": item.product_name,
                "model_number": item.model_number,
                "color_name": item.color_name,
                "size_label": item.size_label,
                "unit_price": item.unit_price,
                "quantity": item.quantity,
                "line_total": line_total
            }
            supabase_admin.table("order_items").insert(item_payload).execute()

            # 3. خصم المخزون تلقائياً إذا كان للمنتج ألوان ومقاسات مسجلة
            if item.product_id and item.quantity > 0:
                try:
                    # محاولة البحث عن المتغير وخصم الكمية
                    query = supabase_admin.table("product_colors").select("id").eq("product_id", item.product_id)
                    if item.color_name:
                        query = query.eq("color_name", item.color_name)
                    color_res = query.execute()

                    if color_res.data:
                        for col in color_res.data:
                            color_id = col["id"]
                            v_query = supabase_admin.table("product_variants").select("id, stock_qty").eq("color_id", color_id)
                            if item.size_label:
                                v_query = v_query.eq("size_label", item.size_label)
                            v_res = v_query.execute()

                            if v_res.data:
                                v_rec = v_res.data[0]
                                current_stock = v_rec.get("stock_qty", 0)
                                new_stock = max(0, current_stock - item.quantity)
                                supabase_admin.table("product_variants").update({"stock_qty": new_stock}).eq("id", v_rec["id"]).execute()
                                break # تم الخصم بنجاح
                except Exception as stock_err:
                    print("⚠️ تحذير أثناء تحديث المخزون للبيع الفوري:", repr(stock_err))

        return {
            "status": "success",
            "message": "تم حفظ طلب البيع الفوري وتحديث المخزون بنجاح",
            "order_id": order_id,
            "data": new_order
        }

    except HTTPException:
        raise
    except Exception as e:
        print("❌ Error creating POS order:", repr(e))
        raise HTTPException(status_code=500, detail=str(e))

# ==================== نموذج إعدادات المتجر (Store Settings Model) ====================
class StoreSettingsSchema(BaseModel):
    store_name: str
    phone: Optional[str] = ""
    currency: Optional[str] = "ر.ي (يمني)"
    low_stock_threshold: Optional[int] = 3

# 1. جلب إعدادات المتجر للتاجر الحالي
@app.get("/api/settings")
async def get_store_settings(user_id: str = Depends(get_current_user_id)):
    try:
        response = (
            supabase_admin.table("store_settings")
            .select("*")
            .eq("owner_id", user_id)
            .limit(1)
            .execute()
        )
        
        if not response.data or len(response.data) == 0:
            # إرجاع بيانات افتراضية إذا لم يتم إنشاء سجل مسبق لهذا التاجر
            default_settings = {
                "store_name": "متجري الجديد",
                "phone": "",
                "currency": "ر.ي (يمني)",
                "low_stock_threshold": 3
            }
            return {"status": "success", "data": default_settings}
            
        return {"status": "success", "data": response.data[0]}
    except Exception as e:
        print("❌ Error fetching store settings:", repr(e))
        raise HTTPException(status_code=500, detail=str(e))

# 2. حفظ أو تحديث إعدادات المتجر للتاجر الحالي (باستخدام Upsert)
@app.post("/api/settings")
async def save_store_settings(
    settings: StoreSettingsSchema,
    user_id: str = Depends(get_current_user_id)
):
    try:
        payload = {
            "owner_id": user_id,
            "store_name": settings.store_name,
            "phone": settings.phone,
            "currency": settings.currency,
            "low_stock_threshold": settings.low_stock_threshold,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        
        # استخدام upsert المباشر لتحديث السجل أو إدخاله إذا لم يكن موجوداً
        res = (
            supabase_admin.table("store_settings")
            .upsert(payload, on_conflict="owner_id")
            .execute()
        )
            
        return {
            "status": "success",
            "message": "تم حفظ الإعدادات بنجاح",
            "data": res.data
        }
    except Exception as e:
        print("❌ Error saving store settings:", repr(e))
        raise HTTPException(status_code=500, detail=str(e))


# =============================نموذج التقارير =============================

@app.get("/api/reports/summary")
async def get_sales_reports(user_id: str = Depends(get_current_user_id)):
    try:
        orders_res = (
            supabase_admin.table("orders")
            .select("total, subtotal, discount, status, created_at, order_items(quantity, unit_price, product_id)")
            .eq("owner_id", user_id)
            .execute()
        )

        orders = orders_res.data or []

        total_sales = sum(o.get("total", 0) for o in orders if o.get("status") != "cancelled")
        total_orders_count = len([o for o in orders if o.get("status") != "cancelled"])
        cancelled_orders_count = len([o for o in orders if o.get("status") == "cancelled"])

        total_items_sold = 0
        for order in orders:
            if order.get("status") != "cancelled":
                for item in order.get("order_items", []):
                    total_items_sold += item.get("quantity", 0)

        return {
            "status": "success",
            "data": {
                "total_sales": total_sales,
                "total_orders_count": total_orders_count,
                "cancelled_orders_count": cancelled_orders_count,
                "total_items_sold": total_items_sold
            }
        }
    except Exception as e:
        print("❌ Error fetching reports:", repr(e))
        raise HTTPException(status_code=500, detail=str(e))


# ==================== مسار الحذف المنطقي للمنتج (Soft Delete) ====================
@app.delete("/api/products/{product_id}")
async def delete_product(
    product_id: str,
    user_id: str = Depends(get_current_user_id)
):
    try:
        # 1. التأكد أن المنتج يخص التاجر الحالي
        check_prod = (
            supabase_admin.table("products")
            .select("id, name")
            .eq("id", product_id)
            .eq("owner_id", user_id)
            .execute()
        )

        if not check_prod.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="المنتج غير موجود أو ليس لديك صلاحية لحذفه"
            )

        # 2. فحص ما إذا كان المنتج مرتبطاً بطلبات نشطة أو معلقة لم تكتمل
        active_items_res = (
            supabase_admin.table("order_items")
            .select("order_id, orders(status)")
            .eq("product_id", product_id)
            .execute()
        )
        
        if active_items_res.data:
            for item in active_items_res.data:
                order_status = item.get("orders", {}).get("status")
                if order_status and order_status not in ["completed", "cancelled"]:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="لا يمكن حذف المنتج لأنه مرتبط بطلب نشط قيد التنفيذ حالياً"
                    )

        # 3. تطبيق الحذف المنطقي (Soft Delete) بدلاً من الحذف النهائي
        # نحول حالته إلى archived ونعطل ظهوره لكي لا يؤثر على الفواتير والسجلات التاريخية
        update_res = (
            supabase_admin.table("products")
            .update({
                "status": "archived",
                "updated_at": datetime.now(timezone.utc).isoformat()
            })
            .eq("id", product_id)
            .eq("owner_id", user_id)
            .execute()
        )

        return {
            "status": "success",
            "message": "تم أرشفة وحذف المنتج منطقياً بنجاح مع الحفاظ على السجلات التاريخية للفواتير"
        }

    except HTTPException:
        raise
    except Exception as e:
        print("❌ Error soft-deleting product:", repr(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"خطأ أثناء أرشفة المنتج: {str(e)}"
        )

# ==================== جلب التفاصيل الكاملة للمنتج (لشاشة التعديل) ====================
@app.get("/api/products/{product_id}/details")
async def get_product_full_details(
    product_id: str,
    user_id: str = Depends(get_current_user_id)
):
    try:
        prod_res = (
            supabase_admin.table("products")
            .select("*, product_colors(id, color_name, color_code, product_variants(id, size_label, stock_qty)), product_images(id, image_url, image_type, color_id)")
            .eq("id", product_id)
            .eq("owner_id", user_id)
            .single()
            .execute()
        )
        if not prod_res.data:
            raise HTTPException(status_code=404, detail="المنتج غير موجود")

        return {"status": "success", "data": prod_res.data}
    except HTTPException:
        raise
    except Exception as e:
        print("❌ Error fetching product details:", repr(e))
        raise HTTPException(status_code=500, detail=f"خطأ في جلب تفاصيل المنتج: {str(e)}")


# ==================== مسار تعديل منتج (مطابق للقواعد الاحترافية بالكامل) ====================
@app.put("/api/products/{product_id}")
async def update_product(
    product_id: str,
    request: Request,
    user_id: str = Depends(get_current_user_id)
):
    try:
        form = await request.form()

        model_number = form.get("model_number")
        name = form.get("name")
        retail_price_str = form.get("retail_price")
        wholesale_price_str = form.get("wholesale_price")
        product_status = form.get("status", "draft")
        description = form.get("description")
        colors_json = form.get("colors_json", "[]")
        deleted_image_ids_json = form.get("deleted_image_ids", "[]")

        # 1. التحقق من أن الأسعار أرقام صحيحة وليست سالبة
        try:
            retail_price = float(retail_price_str)
            if retail_price < 0:
                raise ValueError
        except Exception:
            raise HTTPException(status_code=400, detail="سعر التجزئة يجب أن يكون رقماً صحيحاً وغير سالب")

        wholesale_price = None
        if wholesale_price_str and wholesale_price_str != "null" and wholesale_price_str.strip() != "":
            try:
                wholesale_price = float(wholesale_price_str)
                if wholesale_price < 0:
                    raise ValueError
            except Exception:
                raise HTTPException(status_code=400, detail="سعر الجملة يجب أن يكون رقماً غير سالب")

        # 2. جلب بيانات المنتج الحالية للتأكد من الملكية ومعرفة هل تغير رقم الموديل؟
        current_prod_res = (
            supabase_admin.table("products")
            .select("model_number, owner_id")
            .eq("id", product_id)
            .eq("owner_id", user_id)
            .execute()
        )

        if not current_prod_res.data:
            raise HTTPException(status_code=404, detail="المنتج غير موجود أو ليس لديك صلاحية لتعديله")

        old_model_number = current_prod_res.data[0]["model_number"]

        # 3. التحقق من أن رقم الموديل الجديد غير مستخدم لمنتج آخر لنفس التاجر
        if model_number != old_model_number:
            conflict_res = (
                supabase_admin.table("products")
                .select("id")
                .eq("owner_id", user_id)
                .eq("model_number", model_number)
                .neq("id", product_id)
                .execute()
            )
            if conflict_res.data and len(conflict_res.data) > 0:
                raise HTTPException(status_code=400, detail="رقم الموديل هذا مستخدم بالفعل لمنتج آخر، اختر رقماً فريداً")

        colors_data = json.loads(colors_json)
        deleted_image_ids = json.loads(deleted_image_ids_json)

        # 4. التحقق من عدم حذف أي لون أو مقاس مرتبط بمبيعات أو فواتير سابقة
        sold_items_res = (
            supabase_admin.table("order_items")
            .select("color_name, size_label")
            .eq("product_id", product_id)
            .execute()
        )
        sold_combinations = {
            (item.get("color_name"), item.get("size_label"))
            for item in (sold_items_res.data or [])
        }

        new_combinations = set()
        for c in colors_data:
            c_name = str(c.get("color_name", "")).strip()
            for v in c.get("variants", []):
                s_label = str(v.get("size_label", "")).strip()
                if not s_label:
                    s_label = "الافتراضي"
                qty_val = int(v.get("stock_qty", 0))
                if qty_val < 0:
                    raise HTTPException(status_code=400, detail="كمية المخزون بالمقاس لا يمكن أن تكون سالبة")
                new_combinations.add((c_name, s_label))

        for sold_color, sold_size in sold_combinations:
            if sold_color and sold_size and (sold_color, sold_size) not in new_combinations:
                raise HTTPException(
                    status_code=400,
                    detail=f"لا يمكن حذف اللون ({sold_color}) والمقاس ({sold_size}) لارتباطه بفواتير ومبيعات سابقة. يمكنك تصفير كميته (0) بدلاً من حذفه."
                )

        # 5. تحديث البيانات الأساسية (مع بقاء product_id ثابتاً)
        prod_data = {
            "model_number": model_number,
            "name": name,
            "description": description,
            "retail_price": retail_price,
            "wholesale_price": wholesale_price,
            "status": product_status,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }

        update_res = (
            supabase_admin.table("products")
            .update(prod_data)
            .eq("id", product_id)
            .execute()
        )

        if not update_res.data:
            raise HTTPException(status_code=500, detail="فشل تحديث بيانات المنتج الأساسية")

        qr_code_value = f"BAR-{model_number.upper()}"

        # 6. إدارة الصور القديمة (حذف الصور التي أزالها المستخدم + إعادة ختم الصور المتبقية إذا تغير الموديل)
        if deleted_image_ids:
            supabase_admin.table("product_images").delete().in_("id", deleted_image_ids).eq("product_id", product_id).execute()

        if model_number != old_model_number:
            existing_imgs = supabase_admin.table("product_images").select("*").eq("product_id", product_id).execute()
            async with httpx.AsyncClient() as client:
                for img_rec in (existing_imgs.data or []):
                    try:
                        res_img = await client.get(img_rec["image_url"])
                        if res_img.status_code == 200:
                            new_bytes = await apply_qr_overlay(res_img.content, qr_code_value)
                            new_path = f"products/{product_id}/updated_{os.urandom(4).hex()}.jpg"
                            supabase_admin.storage.from_("product-images").upload(
                                new_path, new_bytes, file_options={"content-type": "image/jpeg"}
                            )
                            new_url = supabase_admin.storage.from_("product-images").get_public_url(new_path)
                            supabase_admin.table("product_images").update({"image_url": new_url}).eq("id", img_rec["id"]).execute()
                    except Exception as img_err:
                        print("⚠️ تحذير أثناء تحديث باركود صورة قديمة:", repr(img_err))

        # 7. تحديث الألوان والمقاسات والكميات بأمان بعد اجتياز فحص المبيعات التاريخية
        old_colors_res = supabase_admin.table("product_colors").select("id").eq("product_id", product_id).execute()
        for col in (old_colors_res.data or []):
            supabase_admin.table("product_variants").delete().eq("color_id", col["id"]).execute()
        supabase_admin.table("product_colors").delete().eq("product_id", product_id).execute()

        for index, color_item in enumerate(colors_data):
            color_name = color_item.get("color_name")
            if not color_name or not str(color_name).strip():
                continue

            color_insert_data = {
                "product_id": product_id,
                "color_name": str(color_name).strip(),
            }
            if color_item.get("color_code"):
                color_insert_data["color_code"] = color_item.get("color_code")

            color_res = supabase_admin.table("product_colors").insert(color_insert_data).execute()

            if color_res.data:
                color_id = color_res.data[0]["id"]

                variants = color_item.get("variants", [])
                if not variants:
                    variants = [{"size_label": "الافتراضي", "stock_qty": 0}]

                for variant in variants:
                    size_label = str(variant.get("size_label", "")).strip()
                    if not size_label:
                        size_label = "الافتراضي"

                    qty = int(variant.get("stock_qty", 0))

                    supabase_admin.table("product_variants").insert({
                        "color_id": color_id,
                        "size_label": size_label,
                        "stock_qty": qty
                    }).execute()

                # رفع صور الألوان الجديدة ودمج QR الموديل الحالي باستخدام الفهرس المطابق
                color_images = form.getlist(f"color_images_{index}")
                for img in color_images:
                    if hasattr(img, "filename") and img.filename:
                        image_bytes = await img.read()
                        processed_bytes = await apply_qr_overlay(image_bytes, qr_code_value)
                        file_name = f"col_{os.urandom(4).hex()}_{os.path.basename(img.filename)}"
                        file_path = f"products/{product_id}/colors/{color_id}/{file_name}"

                        supabase_admin.storage.from_("product-images").upload(
                            file_path, processed_bytes, file_options={"content-type": "image/jpeg"}
                        )
                        public_url = supabase_admin.storage.from_("product-images").get_public_url(file_path)

                        supabase_admin.table("product_images").insert({
                            "product_id": product_id,
                            "color_id": color_id,
                            "image_url": public_url,
                            "image_type": "color"
                        }).execute()

        # 8. رفع الصور العامة الجديدة ودمج QR الموديل الحالي
        general_images = form.getlist("general_images")
        for img in general_images:
            if hasattr(img, "filename") and img.filename:
                image_bytes = await img.read()
                processed_bytes = await apply_qr_overlay(image_bytes, qr_code_value)
                file_name = f"gen_{os.urandom(4).hex()}_{os.path.basename(img.filename)}"
                file_path = f"products/{product_id}/general/{file_name}"

                supabase_admin.storage.from_("product-images").upload(
                    file_path, processed_bytes, file_options={"content-type": "image/jpeg"}
                )
                public_url = supabase_admin.storage.from_("product-images").get_public_url(file_path)

                supabase_admin.table("product_images").insert({
                    "product_id": product_id,
                    "image_url": public_url,
                    "image_type": "general"
                }).execute()

        return {
            "status": "success",
            "message": "تم تحديث المنتج والكميات والباركود بنجاح مع الحفاظ على سلامة السجلات التاريخية",
            "data": update_res.data[0]
        }

    except HTTPException:
        raise
    except Exception as e:
        print("❌ Error updating product securely:", repr(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"خطأ أثناء تحديث المنتج: {str(e)}"
        )


# ==================== تهيئة اتصال قاعدة البيانات المركزية المستقلة ====================
CENTRAL_SUPABASE_URL = os.getenv("CENTRAL_SUPABASE_URL")
CENTRAL_SUPABASE_SERVICE_KEY = os.getenv("CENTRAL_SUPABASE_SERVICE_KEY")
MERCHANT_ID = os.getenv("MERCHANT_ID")
My_WHATSAPP_NUMBER = os.getenv("My_WHATSAPP_NUMBER", "+967770000000") # رقم افتراضي احتياطي
central_supabase: Optional[Client] = None
if CENTRAL_SUPABASE_URL and CENTRAL_SUPABASE_SERVICE_KEY:
    central_supabase = create_client(CENTRAL_SUPABASE_URL, CENTRAL_SUPABASE_SERVICE_KEY)

# إعداد عميل OpenAI Vision AI
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
openai_client = AsyncOpenAI(api_key=OPENAI_API_KEY) if OPENAI_API_KEY else None


# دالة لجلب أو تسجيل حصة التاجر في قاعدة البيانات المركزية المنفصلة
async def _get_or_create_central_quota(merchant_id: str):
    if not central_supabase:
        raise HTTPException(
            status_code=500, 
            detail="اتصال قاعدة البيانات المركزية غير مهيأ في متغيرات البيئة."
        )
    try:
        res = (
            central_supabase.table("merchant_quotas")
            .select("images_used, allowed_limit, is_subscribed")
            .eq("merchant_id", merchant_id)
            .execute()
        )
        
        if not res.data or len(res.data) == 0:
            new_quota = {
                "merchant_id": merchant_id,
                "images_used": 0,
                "allowed_limit": 50,
                "is_subscribed": 0,
                "updated_at": datetime.now(timezone.utc).isoformat()
            }
            central_supabase.table("merchant_quotas").insert(new_quota).execute()
            return 0, 50, 0
        
        quota = res.data[0]
        return (
            quota.get("images_used", 0), 
            quota.get("allowed_limit", 50), 
            quota.get("is_subscribed", 0)
        )
    except Exception as e:
        print("❌ Error in Central DB quota check:", repr(e))
        raise HTTPException(status_code=500, detail="تعذر التحقق من رصيد التاجر في القاعدة المركزية")


# ==================== مسار تحليل الكرتون بـ Vision AI والتحقق من الحصة ====================
@app.post("/api/scan-carton", dependencies=[Depends(get_current_user_id)])
async def scan_carton_with_ai(
    file: UploadFile = File(...),
):
    if not MERCHANT_ID:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="معرّف التاجر غير مهيأ في متغيرات البيئة.",
        )

    merchant_id = MERCHANT_ID

    if not openai_client:
        raise HTTPException(status_code=500, detail="مفتاح OPENAI_API_KEY غير معرّف.")

    try:
        # 1. التحقق من حصة التاجر في القاعدة المركزية المنفصلة
        images_used, allowed_limit, is_subscribed = await _get_or_create_central_quota(merchant_id)

        if images_used >= allowed_limit:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error_code": "LIMIT_EXCEEDED",
                    "message": "عذراً، لقد استهلكت رصيدك المتاح من المسح الذكي. لتفعيل 150 صورة جديدة، يرجى تحويل مبلغ 1.5 دولار إلى حسابنا في بنك الكريمي والتواصل مع المطور عبر الواتساب.",
                    "whatsapp_number": My_WHATSAPP_NUMBER, # يقرأه من متغير البيئة في Render بنجاح
                    "subscription_price": "1.5$"
                }
            )

        # 2. قراءة الصورة المرسلة من التطبيق
        image_bytes = await file.read()
        try:
            with Image.open(io.BytesIO(image_bytes)) as uploaded_image:
                image_format = uploaded_image.format
                uploaded_image.verify()
            image_mime_type = Image.MIME.get(image_format)
        except (OSError, ValueError):
            raise HTTPException(
                status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                detail="الملف المرفوع ليس صورة صالحة.",
            )

        if not image_mime_type or not image_mime_type.startswith("image/"):
            raise HTTPException(
                status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                detail="نوع الصورة المرفوعة غير مدعوم.",
            )

        # 3. تحليل الصورة عبر OpenAI Responses API
        image_base64 = base64.b64encode(image_bytes).decode("ascii")
        image_data_url = f"data:{image_mime_type};base64,{image_base64}"
        response = await openai_client.responses.create(
            model="gpt-6-luna",
            input=[
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "input_text",
                            "text": (
                                "استخرج من صورة كرتون الأحذية هذه البيانات بدقة بصيغة JSON فقط: "
                                "تحتوي على مفتاحين أساسيين: 'model_number' (رقم الموديل مجرداً من الحروف إن وجد)، "
                                "و 'colors' (قائمة بأسماء الألوان المستخرجة باللغة العربية حصرياً مثل: أسود، بني، عسلي، كحلي، أبيض، رمادي). "
                                "تجنب تماماً أي ألوان وهمية أو غير واضحة من كود أو تحذيرات الكرتون."
                            ),
                        },
                        {
                            "type": "input_image",
                            "image_url": image_data_url,
                            "detail": "auto",
                        },
                    ],
                }
            ],
            text={"format": {"type": "json_object"}},
        )

        # 4. تحديث العداد في القاعدة المركزية بزيادة 1
        new_used_count = images_used + 1
        central_supabase.table("merchant_quotas").update({
            "images_used": new_used_count,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }).eq("merchant_id", merchant_id).execute()

        return {
            "status": "success",
            "remaining_images": allowed_limit - new_used_count,
            "data": json.loads(response.output_text)
        }

    except HTTPException:
        raise
    except Exception as e:
        print("❌ Error in Vision AI scan:", repr(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"فشل معالجة الصورة: {str(e)}"
        )


# ==================== تشغيل الخادم ====================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
