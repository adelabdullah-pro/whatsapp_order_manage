import os
import json
import base64
import hashlib
import hmac
import io
import re
import unicodedata
from bidi.algorithm import get_display
from typing import Optional, List, Any
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
from starlette.concurrency import run_in_threadpool
from pydantic import BaseModel, EmailStr
from supabase import create_client, Client
from dotenv import load_dotenv
import qrcode
from PIL import Image
import httpx
import cv2
from datetime import datetime, timezone
from time import perf_counter
import numpy as np
from difflib import get_close_matches
from openai import AsyncOpenAI
import arabic_reshaper
from reportlab.lib.pagesizes import A4
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas


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


async def _execute_db_query(query: Any) -> Any:
    return await run_in_threadpool(query.execute)


# ==================== إعدادات WhatsApp API ====================

WHATSAPP_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN")
META_APP_SECRET = os.getenv("META_APP_SECRET")
WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN")
PHONE_NUMBER_ID = os.getenv("PHONE_NUMBER_ID")
MAX_SCAN_IMAGE_BYTES = 10 * 1024 * 1024


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
        user_response = await run_in_threadpool(supabase.auth.get_user, token)
        
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

def _apply_qr_overlay_sync(image_bytes: bytes, qr_data: str) -> bytes:
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


async def apply_qr_overlay(image_bytes: bytes, qr_data: str) -> bytes:
    return await run_in_threadpool(_apply_qr_overlay_sync, image_bytes, qr_data)


# ==================== جلب المنتجات ====================
@app.get("/api/products")
def get_products(user_id: str = Depends(get_current_user_id)):
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

        prod_res = await _execute_db_query(
            supabase.table("products")
            .insert(prod_data)
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

                await run_in_threadpool(
                    supabase.storage.from_("product-images").upload,
                    file_path,
                    processed_bytes,
                    file_options={"content-type": "image/jpeg"},
                )

                public_url = (
                    supabase.storage
                    .from_("product-images")
                    .get_public_url(file_path)
                )

                await _execute_db_query(
                    supabase.table("product_images").insert({
                        "product_id": product_id,
                        "image_url": public_url,
                        "image_type": "general"
                    })
                )

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

            color_res = await _execute_db_query(
                supabase.table("product_colors").insert(color_insert_data)
            )

            if color_res.data:
                color_id = color_res.data[0]["id"]

                variants = color_item.get("variants", [])
                if not variants:
                    variants = [{
                        "size_label": "الافتراضي",
                        "stock_qty": color_item.get("stock_qty", 0),
                    }]

                for variant in variants:
                    size_label = str(variant.get("size_label") or "").strip() or "الافتراضي"
                    await _execute_db_query(
                        supabase.table("product_variants").insert({
                            "color_id": color_id,
                            "size_label": size_label,
                            "stock_qty": variant.get("stock_qty", 0)
                        })
                    )

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

                        await run_in_threadpool(
                            supabase.storage.from_("product-images").upload,
                            file_path,
                            processed_bytes,
                            file_options={"content-type": "image/jpeg"},
                        )

                        public_url = (
                            supabase.storage
                            .from_("product-images")
                            .get_public_url(file_path)
                        )

                        await _execute_db_query(
                            supabase.table("product_images").insert({
                                "product_id": product_id,
                                "color_id": color_id,
                                "image_url": public_url,
                                "image_type": "color"
                            })
                        )

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
def get_product_images(
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
async def _legacy_receive_whatsapp_message(request: Request):
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
                    db_res = await _execute_db_query(
                        supabase_admin.table("products")
                        .select("*, product_colors(id, color_name, product_variants(id, size_label, stock_qty))")
                        .ilike("model_number", model_number)
                    )

                    if not db_res.data or len(db_res.data) == 0:
                        await send_whatsapp_message(sender_phone, f"❌ الباركود ({barcode_value}) غير مسجل في نظامنا.")
                        continue

                    product = db_res.data[0]

                    # التحقق من اسم العميل المسبق في قاعدة البيانات
                    existing_customer_res = await _execute_db_query(
                        supabase_admin.table("orders")
                        .select("customer_name")
                        .eq("customer_phone", sender_phone)
                        .not_.eq("customer_name", "عميل واتساب")
                        .limit(1)
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
                        
                        profile_res = await _execute_db_query(
                            supabase_admin.table("profiles")
                            .select("id")
                            .limit(1)
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

                        order_res = await _execute_db_query(
                            supabase_admin.table("orders").insert(order_payload)
                        )

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

                            await _execute_db_query(
                                supabase_admin.table("order_items").insert(item_payload)
                            )

                            variant_res = await _execute_db_query(
                                supabase_admin.table("product_variants")
                                .select("id, stock_qty")
                                .eq("color_id", selected_color_id)
                                .eq("size_label", selected_size)
                            )

                            if variant_res.data and len(variant_res.data) > 0:
                                variant_record = variant_res.data[0]
                                current_stock = variant_record.get("stock_qty", 0)
                                new_stock = max(0, current_stock - quantity)

                                await _execute_db_query(
                                    supabase_admin.table("product_variants")
                                    .update({"stock_qty": new_stock})
                                    .eq("id", variant_record["id"])
                                )

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


def normalize_order_text(text: str) -> str:
    normalized = []
    for character in text.casefold():
        if unicodedata.category(character) == "Mn":
            continue
        try:
            normalized.append(str(unicodedata.digit(character)))
            continue
        except (TypeError, ValueError):
            pass
        normalized.append({"أ": "ا", "إ": "ا", "آ": "ا", "ى": "ي"}.get(character, character))
    words = re.sub(r"[^\w]+", " ", "".join(normalized)).split()
    return " ".join(
        word[2:] if word.startswith("ال") and len(word) > 2 else word
        for word in words
    )


NO_SIZE_LABELS = {
    "افتراضي",
    "بدون مقاس",
    "مقاس موحد",
    "موحد",
    "one size",
    "free size",
    "default",
}

COLOR_TEXT_CANONICAL = {
    "اسود": "black",
    "سوداء": "black",
    "black": "black",
    "ابيض": "white",
    "بيضاء": "white",
    "white": "white",
    "احمر": "red",
    "حمراء": "red",
    "red": "red",
    "ازرق": "blue",
    "زرقاء": "blue",
    "blue": "blue",
    "اخضر": "green",
    "خضراء": "green",
    "green": "green",
    "اصفر": "yellow",
    "صفراء": "yellow",
    "yellow": "yellow",
    "بني": "brown",
    "بنية": "brown",
    "brown": "brown",
    "وردي": "pink",
    "وردية": "pink",
    "pink": "pink",
    "بنفسجي": "purple",
    "بنفسجية": "purple",
    "purple": "purple",
    "رمادي": "gray",
    "رمادية": "gray",
    "gray": "gray",
    "grey": "gray",
}


def color_terms_match(caption: str, color_name: str) -> bool:
    normalized_caption = f" {normalize_order_text(caption)} "
    normalized_name = normalize_order_text(color_name)
    canonical_name = COLOR_TEXT_CANONICAL.get(normalized_name)
    accepted_names = {normalized_name}
    if canonical_name:
        accepted_names.update(
            name for name, canonical in COLOR_TEXT_CANONICAL.items()
            if canonical == canonical_name
        )
    return any(f" {name} " in normalized_caption for name in accepted_names)


def find_requested_variant(caption: str, colors: list):
    normalized_caption = f" {normalize_order_text(caption)} "
    matched_colors = [
        color for color in colors
        if color_terms_match(caption, color.get("color_name", ""))
    ]
    if len(matched_colors) != 1:
        return None, None, "color"

    color = matched_colors[0]
    variants = color.get("product_variants", [])
    sized_variants = [
        variant for variant in color.get("product_variants", [])
        if normalize_order_text(str(variant.get("size_label", ""))) not in NO_SIZE_LABELS
    ]
    if sized_variants:
        matched_variants = [
            variant for variant in sized_variants
            if f" {normalize_order_text(str(variant.get('size_label', '')))} " in normalized_caption
        ]
        if len(matched_variants) != 1:
            return color, None, "size"
        return color, matched_variants[0], None

    default_variants = [
        variant for variant in variants
        if normalize_order_text(str(variant.get("size_label", ""))) in NO_SIZE_LABELS
    ]
    if len(default_variants) != 1:
        return color, None, "inventory"
    return color, default_variants[0], None


def save_whatsapp_order(sender_phone: str, session: dict):
    variant_id = session["variant_id"]
    variant_res = (
        supabase_admin.table("product_variants")
        .select("id, stock_qty")
        .eq("id", variant_id)
        .execute()
    )
    if not variant_res.data or (variant_res.data[0].get("stock_qty") or 0) < 1:
        return None

    variant = variant_res.data[0]
    current_stock = variant.get("stock_qty", 0)
    order_total = float(session["retail_price"])
    customer_name = session["customer_name"]
    order_payload = {
        "owner_id": session["owner_id"],
        "customer_name": customer_name,
        "customer_phone": sender_phone,
        "source": "whatsapp",
        "status": "new",
        "payment_status": "unpaid",
        "subtotal": order_total,
        "delivery_fee": 0.00,
        "discount": 0.00,
        "total": order_total,
        "currency": "YER",
        "shipping_address": "غير محدد - طلب عبر واتساب",
        "customer_notes": "طلب واتساب؛ الكمية قطعة واحدة",
    }

    order_res = supabase_admin.table("orders").insert(order_payload).execute()
    if not order_res.data:
        raise RuntimeError("فشل إنشاء الطلب")
    order_id = order_res.data[0]["id"]

    item_payload = {
        "order_id": order_id,
        "product_id": session["product_id"],
        "product_name": session["product_name"],
        "model_number": session["model_number"],
        "color_name": session["color_name"],
        "size_label": session.get("size_label"),
        "unit_price": order_total,
        "quantity": 1,
        "line_total": order_total,
    }
    try:
        supabase_admin.table("order_items").insert(item_payload).execute()
        stock_res = (
            supabase_admin.table("product_variants")
            .update({"stock_qty": current_stock - 1})
            .eq("id", variant_id)
            .eq("stock_qty", current_stock)
            .select("id")
            .execute()
        )
        if not stock_res.data:
            supabase_admin.table("order_items").delete().eq("order_id", order_id).execute()
            supabase_admin.table("orders").delete().eq("id", order_id).execute()
            return None
    except Exception:
        supabase_admin.table("order_items").delete().eq("order_id", order_id).execute()
        supabase_admin.table("orders").delete().eq("id", order_id).execute()
        raise
    return order_id


class CustomerInvoiceRequest(BaseModel):
    customer_phone: str


def is_invoice_request(text: str) -> bool:
    normalized_text = normalize_order_text(text)
    return any(
        term in normalized_text
        for term in (
            "فاتورة", "فاتوره", "فواتير", "invoice",
            "اجمالي طلبات", "اجمالي طلباتي", "مجموع طلبات", "مجموع طلباتي",
        )
    )


_invoice_reshaper = arabic_reshaper.ArabicReshaper(
    configuration={"use_unshaped_instead_of_isolated": True}
)


def _invoice_display_text(text: str) -> str:
    return get_display(_invoice_reshaper.reshape(str(text)))


def _draw_invoice_text(pdf_canvas, x: float, y: float, text: str, font_size: int = 10):
    shaped_text = _invoice_display_text(text)
    pdf_canvas.setFont("Cairo", font_size)
    pdf_canvas.drawRightString(x, y, shaped_text)


def _wrap_invoice_text(text: str, width: float, font_size: int) -> list:
    def fits(value: str) -> bool:
        return pdfmetrics.stringWidth(_invoice_display_text(value), "Cairo", font_size) <= width

    lines = []
    current = ""
    for word in str(text).split():
        candidate = f"{current} {word}" if current else word
        if fits(candidate):
            current = candidate
            continue
        if current:
            lines.append(current)
            current = ""
        for character in word:
            if current and not fits(current + character):
                lines.append(current)
                current = character
            else:
                current += character
    if current:
        lines.append(current)
    return lines or [""]


def build_customer_invoice_pdf(invoice: dict, orders: list) -> bytes:
    font_dir = os.path.join(os.path.dirname(__file__), "assets", "fonts")
    registered_fonts = pdfmetrics.getRegisteredFontNames()
    if "Cairo" not in registered_fonts:
        pdfmetrics.registerFont(TTFont("Cairo", os.path.join(font_dir, "Cairo-Regular.ttf")))

    pdf_buffer = io.BytesIO()
    pdf_canvas = canvas.Canvas(pdf_buffer, pagesize=A4)
    page_width, page_height = A4
    currency = invoice.get("currency") or "YER"
    y = page_height - 48

    right = page_width - 42
    column_rights = [right, right - 220, right - 270, right - 375]
    column_widths = [220, 50, 105, right - 375 - 42]

    pdf_canvas.setFont("Cairo", 18)
    pdf_canvas.drawCentredString(
        page_width / 2, y, _invoice_display_text("فاتورة مجمعة لحجوزات العميل")
    )
    y -= 28
    for text in (
        f"رقم الفاتورة: {str(invoice['id'])[:8]}",
        f"العميل: {invoice.get('customer_name') or ''}",
        f"الهاتف: {invoice.get('customer_phone') or ''}",
        f"التاريخ: {str(invoice.get('created_at') or '')[:10]}",
    ):
        for line in _wrap_invoice_text(text, right - 42, 11):
            if y < 62:
                pdf_canvas.showPage()
                y = page_height - 48
            _draw_invoice_text(pdf_canvas, right, y, line, 11)
            y -= 17
    y -= 8

    def table_header():
        nonlocal y
        if y < 100:
            pdf_canvas.showPage()
            y = page_height - 48
        pdf_canvas.line(42, y, right, y)
        y -= 18
        for x, label in zip(
            column_rights, ("المنتج واللون والمقاس", "الكمية", "سعر الوحدة", "الإجمالي")
        ):
            _draw_invoice_text(pdf_canvas, x - 5, y, label, 9)
        y -= 10
        pdf_canvas.line(42, y, right, y)
        y -= 18

    def ensure_space():
        nonlocal y
        if y < 62:
            pdf_canvas.showPage()
            y = page_height - 48
            table_header()

    table_header()

    for order in orders:
        order_items = order.get("order_items", [])
        if order_items:
            order_date = str(order.get("created_at") or "")[:10]
            for line in _wrap_invoice_text(
                f"الحجز {str(order.get('id', ''))[:8]} - {order_date}", right - 42, 9
            ):
                ensure_space()
                _draw_invoice_text(pdf_canvas, right - 5, y, line, 9)
                y -= 16

        for item in order_items:
            product_details = [item.get("product_name") or "منتج"]
            if item.get("color_name"):
                product_details.append(f"اللون {item['color_name']}")
            if item.get("size_label"):
                product_details.append(f"المقاس {item['size_label']}")
            quantity = item.get("quantity") or 0
            unit_price = item.get("unit_price") or 0
            line_total = item.get("line_total")
            if line_total is None:
                line_total = float(unit_price) * int(quantity)
            values = (
                " - ".join(product_details),
                str(quantity),
                f"{unit_price} {currency}",
                f"{line_total} {currency}",
            )
            wrapped = [
                _wrap_invoice_text(value, width - 10, 9)
                for value, width in zip(values, column_widths)
            ]
            for line_index in range(max(len(lines) for lines in wrapped)):
                ensure_space()
                for x, lines in zip(column_rights, wrapped):
                    if line_index < len(lines):
                        _draw_invoice_text(pdf_canvas, x - 5, y, lines[line_index], 9)
                y -= 14
            y -= 3

    if y < 65:
        pdf_canvas.showPage()
        y = page_height - 48
    pdf_canvas.line(42, y, page_width - 42, y)
    y -= 24
    for line in _wrap_invoice_text(
        f"الإجمالي الكلي: {invoice.get('total', 0)} {currency}", right - 42, 14
    ):
        if y < 62:
            pdf_canvas.showPage()
            y = page_height - 48
        _draw_invoice_text(pdf_canvas, right, y, line, 14)
        y -= 18
    pdf_canvas.save()
    return pdf_buffer.getvalue()


async def send_whatsapp_document(to_phone: str, document: bytes, filename: str, caption: str) -> bool:
    if not WHATSAPP_TOKEN or not PHONE_NUMBER_ID:
        print("❌ تعذر إرسال الفاتورة: إعدادات WhatsApp غير مكتملة")
        return False

    headers = {"Authorization": f"Bearer {WHATSAPP_TOKEN}"}
    upload_url = f"https://graph.facebook.com/v19.0/{PHONE_NUMBER_ID}/media"
    message_url = f"https://graph.facebook.com/v19.0/{PHONE_NUMBER_ID}/messages"

    async with httpx.AsyncClient(timeout=30) as client:
        upload_response = await client.post(
            upload_url,
            headers=headers,
            data={
                "messaging_product": "whatsapp",
                "type": "application/pdf",
            },
            files={"file": (filename, document, "application/pdf")},
        )
        if upload_response.status_code != 200:
            print("❌ WhatsApp invoice upload failed:", upload_response.status_code, upload_response.text)
            return False

        media_id = upload_response.json().get("id")
        if not media_id:
            print("❌ WhatsApp invoice upload returned no media id")
            return False

        send_response = await client.post(
            message_url,
            headers={**headers, "Content-Type": "application/json"},
            json={
                "messaging_product": "whatsapp",
                "to": to_phone,
                "type": "document",
                "document": {
                    "id": media_id,
                    "filename": filename,
                    "caption": caption,
                },
            },
        )
        if send_response.status_code != 200:
            print("❌ WhatsApp invoice delivery failed:", send_response.status_code, send_response.text)
            return False
    return True


def load_customer_invoice_pdf(invoice_id: str, owner_id: str):
    invoice_response = (
        supabase_admin.table("customer_invoices")
        .select("*")
        .eq("id", invoice_id)
        .eq("owner_id", owner_id)
        .execute()
    )
    if not invoice_response.data:
        return None

    invoice = invoice_response.data[0]
    orders_response = (
        supabase_admin.table("orders")
        .select("*, order_items(*)")
        .eq("owner_id", owner_id)
        .eq("invoice_id", invoice_id)
        .order("created_at")
        .execute()
    )
    orders = orders_response.data or []
    return invoice, orders, build_customer_invoice_pdf(invoice, orders)


async def deliver_customer_invoice(invoice: dict, pdf_bytes: bytes, customer_phone: str) -> bool:
    try:
        whatsapp_sent = await send_whatsapp_document(
            customer_phone,
            pdf_bytes,
            f"invoice_{str(invoice['id'])[:8]}.pdf",
            f"فاتورة حجوزاتك رقم {str(invoice['id'])[:8]}",
        )
    except httpx.HTTPError as error:
        print("❌ WhatsApp invoice delivery request failed:", repr(error))
        whatsapp_sent = False
    if whatsapp_sent:
        try:
            await _execute_db_query(
                supabase_admin.table("customer_invoices")
                .update({"status": "sent"})
                .eq("id", invoice["id"])
            )
        except Exception as error:
            print("❌ Failed to update invoice delivery status:", repr(error))
    return whatsapp_sent


async def prepare_customer_invoice(owner_id: str, customer_phone: str):
    invoice_result = await _execute_db_query(
        supabase_admin.rpc(
            "create_customer_invoice",
            {"p_owner_id": owner_id, "p_customer_phone": customer_phone},
        )
    )
    invoice_result = invoice_result.data
    if isinstance(invoice_result, list) and invoice_result:
        invoice_result = invoice_result[0]
    if not isinstance(invoice_result, dict) or not invoice_result.get("invoice_id"):
        return None

    invoice_data = await run_in_threadpool(
        load_customer_invoice_pdf,
        str(invoice_result["invoice_id"]),
        owner_id,
    )
    if not invoice_data:
        raise RuntimeError("تم إنشاء الفاتورة لكن تعذر جلب بياناتها")
    invoice, _, pdf_bytes = invoice_data
    whatsapp_sent = await deliver_customer_invoice(invoice, pdf_bytes, customer_phone)

    return {
        "invoice": invoice,
        "pdf": pdf_bytes,
        "whatsapp_sent": whatsapp_sent,
    }


@app.post("/api/invoices/customer")
async def create_customer_invoice_endpoint(
    request_data: CustomerInvoiceRequest,
    user_id: str = Depends(get_current_user_id),
):
    try:
        customer_phone = request_data.customer_phone.strip()
        result = await prepare_customer_invoice(user_id, customer_phone)
        if not result:
            latest = await _execute_db_query(
                supabase_admin.table("customer_invoices")
                .select("id")
                .eq("owner_id", user_id)
                .eq("customer_phone", customer_phone)
                .eq("status", "sent")
                .order("created_at", desc=True)
                .limit(1)
            )
            if not latest.data:
                raise HTTPException(
                    status_code=404,
                    detail="لا توجد حجوزات غير مفوترة أو فاتورة سابقة لهذا العميل",
                )
            invoice_data = await run_in_threadpool(
                load_customer_invoice_pdf,
                str(latest.data[0]["id"]),
                user_id,
            )
            if not invoice_data:
                raise RuntimeError("تعذر جلب الفاتورة السابقة")
            invoice, _, pdf_bytes = invoice_data
            result = {
                "invoice": invoice,
                "pdf": pdf_bytes,
                "whatsapp_sent": await deliver_customer_invoice(invoice, pdf_bytes, customer_phone),
            }
        invoice_id = result["invoice"]["id"]
        return Response(
            content=result["pdf"],
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'inline; filename="invoice_{str(invoice_id)[:8]}.pdf"',
                "X-Invoice-Id": str(invoice_id),
                "X-WhatsApp-Sent": str(result["whatsapp_sent"]).lower(),
            },
        )
    except HTTPException:
        raise
    except Exception as error:
        print("❌ Failed to create customer invoice:", repr(error))
        raise HTTPException(status_code=500, detail="تعذر إنشاء فاتورة العميل")


@app.get("/api/invoices/{invoice_id}/pdf")
def get_customer_invoice_pdf(
    invoice_id: str,
    user_id: str = Depends(get_current_user_id),
):
    try:
        invoice_data = load_customer_invoice_pdf(invoice_id, user_id)
        if not invoice_data:
            raise HTTPException(status_code=404, detail="الفاتورة غير موجودة")
        invoice, _, pdf_bytes = invoice_data
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'inline; filename="invoice_{str(invoice["id"])[:8]}.pdf"',
                "X-Invoice-Id": str(invoice["id"]),
            },
        )
    except HTTPException:
        raise
    except Exception as error:
        print("❌ Failed to load customer invoice:", repr(error))
        raise HTTPException(status_code=500, detail="تعذر جلب الفاتورة")


@app.post("/webhook")
async def receive_whatsapp_message(request: Request):
    raw_body = await request.body()
    verify_meta_signature(raw_body, request.headers.get("X-Hub-Signature-256"))

    try:
        body = json.loads(raw_body)
        for entry in body.get("entry", []):
            for change in entry.get("changes", []):
                for message in change.get("value", {}).get("messages", []):
                    sender_phone = message.get("from")
                    if not sender_phone:
                        continue

                    session = USER_SESSIONS.get(sender_phone, {})
                    if message.get("type") == "image":
                        image = message.get("image", {})
                        barcode_value = await download_and_decode_whatsapp_image(image.get("id"))
                        if not barcode_value:
                            await send_whatsapp_message(
                                sender_phone,
                                "لم نتمكن من قراءة باركود المنتج. أرسل صورة واضحة للمنتج واكتب اللون والمقاس في وصف الصورة، مثل: أسود 40.",
                            )
                            continue

                        model_number = barcode_value.strip()
                        if model_number.upper().startswith("BAR-"):
                            model_number = model_number[4:].strip()

                        product_res = await _execute_db_query(
                            supabase_admin.table("products")
                            .select("id, owner_id, model_number, name, retail_price, product_colors(id, color_name, product_variants(id, size_label, stock_qty))")
                            .ilike("model_number", model_number)
                            .limit(1)
                        )
                        if not product_res.data:
                            await send_whatsapp_message(sender_phone, "المنتج غير مسجل لدينا. أرسل صورة منتج آخر.")
                            continue

                        product = product_res.data[0]
                        caption = image.get("caption", "")
                        color, variant, missing = find_requested_variant(
                            caption, product.get("product_colors", [])
                        )
                        if missing == "color":
                            await send_whatsapp_message(
                                sender_phone,
                                "لم أتعرف على اللون في وصف الصورة. أعد إرسالها مع لون المنتج، وأضف المقاس إذا كان مطلوباً.",
                            )
                            continue
                        if missing == "size":
                            await send_whatsapp_message(
                                sender_phone,
                                f"تعرفت على اللون {color['color_name']}، لكن هذا المنتج له مقاسات. أعد إرسال الصورة واكتب المقاس المطلوب بوضوح.",
                            )
                            continue
                        if missing == "inventory":
                            await send_whatsapp_message(
                                sender_phone,
                                f"لا يوجد مخزون مسجل للون {color['color_name']} حالياً. يرجى التواصل مع التاجر لتحديث المخزون.",
                            )
                            continue
                        if (variant.get("stock_qty") or 0) < 1:
                            requested_variant = (
                                f"اللون {color['color_name']} والمقاس {variant['size_label']}"
                                if normalize_order_text(str(variant.get("size_label", ""))) not in NO_SIZE_LABELS
                                else f"اللون {color['color_name']}"
                            )
                            await send_whatsapp_message(
                                sender_phone,
                                f"عذراً، {requested_variant} غير متوفر حالياً. أرسل صورة منتج آخر.",
                            )
                            continue

                        known_customer_res = await _execute_db_query(
                            supabase_admin.table("orders")
                            .select("customer_name")
                            .eq("owner_id", product["owner_id"])
                            .eq("customer_phone", sender_phone)
                            .not_.eq("customer_name", "عميل واتساب")
                            .limit(1)
                        )
                        customer_name = (
                            known_customer_res.data[0].get("customer_name")
                            if known_customer_res.data else None
                        )
                        session = {
                            "owner_id": product["owner_id"],
                            "product_id": product["id"],
                            "product_name": product["name"],
                            "model_number": product["model_number"],
                            "retail_price": product["retail_price"],
                            "variant_id": variant["id"],
                            "color_name": color["color_name"],
                            "size_label": (
                                None
                                if normalize_order_text(str(variant.get("size_label", ""))) in NO_SIZE_LABELS
                                else variant["size_label"]
                            ),
                            "customer_name": customer_name,
                        }
                        if not customer_name:
                            USER_SESSIONS[sender_phone] = session
                            await send_whatsapp_message(
                                sender_phone,
                                "المنتج متوفر. أرسل اسمك فقط لإكمال الطلب.",
                            )
                            continue
                    elif message.get("type") == "text":
                        incoming_text = message.get("text", {}).get("body", "").strip()
                        if is_invoice_request(incoming_text):
                            try:
                                customer_orders = await _execute_db_query(
                                    supabase_admin.table("orders")
                                    .select("owner_id")
                                    .eq("customer_phone", sender_phone)
                                    .eq("source", "whatsapp")
                                    .order("created_at", desc=True)
                                    .limit(1)
                                )
                                if not customer_orders.data:
                                    await send_whatsapp_message(
                                        sender_phone,
                                        "لا أجد حجوزات مسجلة بهذا الرقم لإصدار فاتورة لها.",
                                    )
                                    continue

                                invoice_result = await prepare_customer_invoice(
                                    customer_orders.data[0]["owner_id"],
                                    sender_phone,
                                )
                                if not invoice_result:
                                    await send_whatsapp_message(
                                        sender_phone,
                                        "لا توجد حجوزات جديدة غير مفوترة لإضافتها إلى فاتورة.",
                                    )
                                elif not invoice_result["whatsapp_sent"]:
                                    await send_whatsapp_message(
                                        sender_phone,
                                        "تم تجهيز الفاتورة، لكن تعذر إرسال ملف PDF حالياً. يرجى المحاولة لاحقاً أو التواصل مع التاجر.",
                                    )
                            except Exception as error:
                                print("❌ Failed to handle WhatsApp invoice request:", repr(error))
                                await send_whatsapp_message(
                                    sender_phone,
                                    "تعذر تجهيز الفاتورة حالياً. يرجى المحاولة لاحقاً.",
                                )
                            continue

                        if incoming_text.casefold() in {"إلغاء", "الغاء", "cancel", "reset"}:
                            USER_SESSIONS.pop(sender_phone, None)
                            await send_whatsapp_message(sender_phone, "تم إلغاء الطلب الحالي.")
                            continue
                        if not session:
                            await send_whatsapp_message(
                                sender_phone,
                                "لبدء الطلب، أرسل صورة المنتج واكتب اللون في وصفها، وأضف المقاس إذا كان مطلوباً.",
                            )
                            continue
                        if not incoming_text:
                            await send_whatsapp_message(sender_phone, "أرسل اسمك فقط لإكمال الطلب.")
                            continue
                        session["customer_name"] = incoming_text
                    else:
                        continue

                    try:
                        order_id = await run_in_threadpool(
                            save_whatsapp_order,
                            sender_phone,
                            session,
                        )
                    except Exception as error:
                        print("❌ Failed to save WhatsApp order:", repr(error))
                        await send_whatsapp_message(
                            sender_phone,
                            "تعذر تسجيل الطلب حالياً. أعد المحاولة بعد قليل بإرسال صورة المنتج مرة أخرى.",
                        )
                        continue

                    if not order_id:
                        USER_SESSIONS.pop(sender_phone, None)
                        await send_whatsapp_message(
                            sender_phone,
                            "عذراً، نفد هذا المقاس للتو. أرسل صورة منتج آخر.",
                        )
                        continue

                    USER_SESSIONS.pop(sender_phone, None)
                    await send_whatsapp_message(
                        sender_phone,
                        f"تم تسجيل طلبك بنجاح يا {session['customer_name']}! رقم الطلب: {str(order_id)[:8]}. الكمية: قطعة واحدة.",
                    )

        return {"status": "EVENT_RECEIVED"}
    except Exception as error:
        print("❌ CRITICAL WEBHOOK ERROR:", repr(error))
        return {"status": "error"}


# ==================== دالة تحميل وقراءة الباركود مع القص الذكي للزاوية ====================
def _decode_whatsapp_image(image_bytes: bytes) -> Optional[str]:
    nparr = np.frombuffer(image_bytes, np.uint8)
    img_cv = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

    if img_cv is None:
        return None

    detector = cv2.QRCodeDetector()

    val, _, _ = detector.detectAndDecode(img_cv)
    if val and val.strip():
        print(f"QR decoded from full image: {val}")
        return val.strip()

    h, w, _ = img_cv.shape
    crop_y1 = int(h * 0.65)
    crop_x1 = int(w * 0.65)
    bottom_right_crop = img_cv[crop_y1:h, crop_x1:w]

    val_crop, _, _ = detector.detectAndDecode(bottom_right_crop)
    if val_crop and val_crop.strip():
        print(f"QR decoded from cropped image: {val_crop}")
        return val_crop.strip()

    resized_crop = cv2.resize(
        bottom_right_crop,
        (0, 0),
        fx=2.0,
        fy=2.0,
        interpolation=cv2.INTER_CUBIC,
    )
    gray_crop = cv2.cvtColor(resized_crop, cv2.COLOR_BGR2GRAY)
    clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8))
    enhanced_crop = clahe.apply(gray_crop)

    val_enhanced, _, _ = detector.detectAndDecode(enhanced_crop)
    if val_enhanced and val_enhanced.strip():
        print(f"QR decoded from enhanced crop: {val_enhanced}")
        return val_enhanced.strip()

    print("QR not found in the original or cropped image")
    return None


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

        return await run_in_threadpool(_decode_whatsapp_image, img_res.content)
    except Exception as e:
        print("Failed to download or decode WhatsApp image:", repr(e))
        return None


# ==================== ادارة الطلبات ====================

# نماذج البيانات (Pydantic Models) للتحقق من المدخلات
class OrderStatusUpdate(BaseModel):
    new_status: str  # مثال: new, processing, shipping, completed, cancelled
    cancellation_reason: Optional[str] = None
    notes: Optional[str] = None

# 1. جلب قائمة الطلبات مع إمكانية التصفية والبحث
@app.get("/api/orders")
def get_orders(
    status: Optional[str] = None, 
    search: Optional[str] = None, 
    limit: int = 50,
    user_id: str = Depends(get_current_user_id),
    offset: int = 0,
    customer_phone: Optional[str] = None,
    order_id: Optional[str] = None,
):
    if limit < 1 or limit > 1000 or offset < 0:
        raise HTTPException(status_code=422, detail="Invalid pagination parameters")
    
    try:
        response = (
            supabase_admin.table("orders")
            .select("*, order_items(*)")
            .eq("owner_id", user_id)
        )

        if customer_phone is not None:
            response = response.eq("customer_phone", customer_phone)
        if order_id is not None:
            response = response.eq("id", order_id)

        search_term = (search or "").strip()[:100]
        pending_filter = "status.eq.pending,status.eq.new,status.is.null"
        search_filter = None
        if search_term:
            escaped_search = (
                search_term.replace("\\", "\\\\")
                .replace('"', '\\"')
                .replace("%", "\\%")
                .replace("_", "\\_")
            )
            search_filter = (
                f'customer_name.ilike."%{escaped_search}%",'
                f'customer_phone.ilike."%{escaped_search}%"'
            )

        if status and status != "all":
            if status == "pending":
                pending_query_filter = (
                    f"and(or({pending_filter}),or({search_filter}))"
                    if search_filter
                    else pending_filter
                )
                response = response.or_(pending_query_filter)
            else:
                response = response.eq("status", status)

        if search_filter and status != "pending":
            response = response.or_(search_filter)

        query_res = (
            response.order("created_at", desc=True)
            .order("id", desc=True)
            .range(offset, offset + limit)
            .execute()
        )
        rows = query_res.data or []
        has_more = len(rows) > limit
        orders = rows[:limit]

        return {
            "status": "success",
            "count": len(orders),
            "data": orders,
            "has_more": has_more,
            "offset": offset,
            "limit": limit,
        }
        
    except Exception as e:
        print("❌ Error fetching orders:", repr(e))
        raise HTTPException(status_code=500, detail=str(e))
    
# 2. 🚀 إضافة المسار المفقود لجلب تفاصيل طلب معين (مطلوب لـ OrderDetailsScreen)
@app.get("/api/orders/{order_id}")
def get_order_details(
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
        items = items_res.data or []
        product_ids = list({
            item["product_id"]
            for item in items
            if item.get("product_id") is not None
        })
        images_by_product = {}
        if product_ids:
            images_res = (
                supabase_admin.table("product_images")
                .select("product_id, image_url, image_type")
                .in_("product_id", product_ids)
                .execute()
            )
            for image in images_res.data or []:
                product_id = str(image["product_id"])
                if (
                    product_id not in images_by_product
                    or image.get("image_type") == "general"
                ):
                    images_by_product[product_id] = image.get("image_url")
        for item in items:
            product_id = item.get("product_id")
            item["image_url"] = (
                images_by_product.get(str(product_id))
                if product_id is not None
                else None
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
            "items": items,
            "logs": logs_res.data or [],
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print("❌ Error fetching order details:", repr(e))
        raise HTTPException(status_code=500, detail=str(e))

    
# 3. تحديث حالة الطلب وتسجيل الحركة مع إدارة المخزون باتجاهين (الإلغاء والإعادة)
@app.put("/api/orders/{order_id}/status")
def update_order_status(
    order_id: str,
    data: OrderStatusUpdate,
    user_id: str = Depends(get_current_user_id)
):
    try:
        result = supabase_admin.rpc(
            "transition_order_status",
            {
                "p_order_id": order_id,
                "p_owner_id": user_id,
                "p_new_status": data.new_status,
                "p_cancellation_reason": data.cancellation_reason or "",
                "p_notes": data.notes or "",
            },
        ).execute().data
        if isinstance(result, list) and result:
            result = result[0]
        if not isinstance(result, dict):
            raise RuntimeError("Invalid order status transition response")
        if result.get("not_found"):
            raise HTTPException(status_code=404, detail="الطلب غير موجود")

        return {
            "status": "success",
            "message": f"تم تحديث حالة الطلب إلى ({result['new_status']}) بنجاح وتحديث المخزون تلقائياً",
            "old_status": result.get("old_status"),
            "new_status": result["new_status"],
        }
    except HTTPException:
        raise
    except Exception as e:
        print("❌ Error updating order status:", repr(e))
        raise HTTPException(status_code=500, detail=f"خطأ في تحديث حالة الطلب: {str(e)}")

class OrderPaymentUpdate(BaseModel):
    paid: bool


@app.put("/api/orders/{order_id}/payment")
def update_order_payment(
    order_id: str,
    data: OrderPaymentUpdate,
    user_id: str = Depends(get_current_user_id),
):
    try:
        current = (
            supabase_admin.table("orders")
            .select("id, status, payment_status, paid_at")
            .eq("id", order_id)
            .eq("owner_id", user_id)
            .execute()
        )
        if not current.data:
            raise HTTPException(status_code=404, detail="الطلب غير موجود")
        order = current.data[0]
        if order.get("status") == "cancelled":
            raise HTTPException(status_code=400, detail="لا يمكن تعديل دفع طلب ملغي")
        target = "paid" if data.paid else "unpaid"
        if order.get("payment_status") == target:
            return {"status": "success", "payment_status": target, "paid_at": order.get("paid_at")}

        paid_at = datetime.now(timezone.utc).isoformat() if data.paid else None
        query = (
            supabase_admin.table("orders")
            .update({"payment_status": target, "paid_at": paid_at})
            .eq("id", order_id)
            .eq("owner_id", user_id)
        )
        for field in ("status", "payment_status"):
            value = order.get(field)
            query = query.is_(field, "null") if value is None else query.eq(field, value)
        updated = query.execute()
        if not updated.data:
            raise HTTPException(status_code=409, detail="تغير الطلب، يرجى تحديثه والمحاولة مجددًا")
        return {"status": "success", "payment_status": target, "paid_at": paid_at}
    except HTTPException:
        raise
    except Exception as error:
        print("❌ Failed to update order payment:", repr(error))
        raise HTTPException(status_code=500, detail="تعذر تحديث حالة الدفع")


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
def create_order(
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
            "paid_at": datetime.now(timezone.utc).isoformat() if order_data.status == "completed" else None,
            "subtotal": order_data.subtotal or order_data.total,
            "delivery_fee": 0.00,
            "discount": order_data.discount or 0.00,
            "total": order_data.total,
            "currency": "YER",
            "shipping_address": order_data.shipping_address,
            "customer_notes": f"عملية بيع فوري (POS) - طريقة الدفع: {order_data.payment_type}"
        }

        items_payload = []
        for item in order_data.order_items:
            line_total = item.unit_price * item.quantity
            items_payload.append({
                "product_id": item.product_id,
                "product_name": item.product_name,
                "model_number": item.model_number,
                "color_name": item.color_name,
                "size_label": item.size_label,
                "unit_price": item.unit_price,
                "quantity": item.quantity,
                "line_total": line_total
            })

        result = supabase_admin.rpc(
            "create_pos_order",
            {
                "p_owner_id": user_id,
                "p_order_payload": order_payload,
                "p_items": items_payload,
            },
        ).execute().data
        if isinstance(result, list) and result:
            result = result[0]
        if not isinstance(result, dict) or not result.get("order_id") or not result.get("data"):
            raise RuntimeError("Invalid POS order creation response")

        return {
            "status": "success",
            "message": "تم حفظ طلب البيع الفوري وتحديث المخزون بنجاح",
            "order_id": result["order_id"],
            "data": result["data"],
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
def get_store_settings(user_id: str = Depends(get_current_user_id)):
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
def save_store_settings(
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


@app.get("/api/settings/whatsapp")
async def get_whatsapp_settings(user_id: str = Depends(get_current_user_id)):
    if not WHATSAPP_TOKEN or not PHONE_NUMBER_ID:
        return {
            "status": "success",
            "data": {
                "connected": False,
                "phone_number": None,
            },
        }

    url = f"https://graph.facebook.com/v19.0/{PHONE_NUMBER_ID}"
    headers = {"Authorization": f"Bearer {WHATSAPP_TOKEN}"}

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(
                url,
                headers=headers,
                params={"fields": "display_phone_number"},
            )
        response.raise_for_status()
        phone_number = response.json().get("display_phone_number")
        return {
            "status": "success",
            "data": {
                "connected": True,
                "phone_number": phone_number,
            },
        }
    except httpx.HTTPStatusError as e:
        print("❌ WhatsApp connection check failed:", e.response.status_code)
        return {
            "status": "success",
            "data": {
                "connected": False,
                "phone_number": None,
            },
        }
    except httpx.RequestError as e:
        print("❌ WhatsApp connection check request failed:", repr(e))
        raise HTTPException(
            status_code=502,
            detail="تعذر التحقق من اتصال واتساب",
        )


# =============================نموذج التقارير =============================

@app.get("/api/dashboard")
def get_dashboard(
    start: datetime,
    end: datetime,
    user_id: str = Depends(get_current_user_id),
):
    if start.tzinfo is None or end.tzinfo is None or start >= end:
        raise HTTPException(status_code=422, detail="فترة المبيعات غير صالحة")
    try:
        result = supabase_admin.rpc(
            "dashboard_summary",
            {
                "p_owner_id": user_id,
                "p_start": start.isoformat(),
                "p_end": end.isoformat(),
            },
        ).execute().data
        if not isinstance(result, dict):
            raise RuntimeError("Invalid dashboard summary response")
        return {"status": "success", "data": result}
    except Exception as error:
        print("❌ Failed to load dashboard:", repr(error))
        raise HTTPException(status_code=500, detail="تعذر تحميل بيانات الرئيسية")


@app.get("/api/reports/summary")
def get_sales_reports(user_id: str = Depends(get_current_user_id)):
    try:
        summary = supabase_admin.rpc(
            "sales_report_summary",
            {"p_owner_id": user_id},
        ).execute().data
        if isinstance(summary, list) and summary:
            summary = summary[0]
        if not isinstance(summary, dict):
            raise RuntimeError("Invalid sales summary response")

        return {
            "status": "success",
            "data": summary,
        }
    except Exception as e:
        print("❌ Error fetching reports:", repr(e))
        raise HTTPException(status_code=500, detail=str(e))


# ==================== مسار الحذف المنطقي للمنتج (Soft Delete) ====================
@app.delete("/api/products/{product_id}")
def delete_product(
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
def get_product_full_details(
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
        current_prod_res = await _execute_db_query(
            supabase_admin.table("products")
            .select("model_number, owner_id")
            .eq("id", product_id)
            .eq("owner_id", user_id)
        )

        if not current_prod_res.data:
            raise HTTPException(status_code=404, detail="المنتج غير موجود أو ليس لديك صلاحية لتعديله")

        old_model_number = current_prod_res.data[0]["model_number"]

        # 3. التحقق من أن رقم الموديل الجديد غير مستخدم لمنتج آخر لنفس التاجر
        if model_number != old_model_number:
            conflict_res = await _execute_db_query(
                supabase_admin.table("products")
                .select("id")
                .eq("owner_id", user_id)
                .eq("model_number", model_number)
                .neq("id", product_id)
            )
            if conflict_res.data and len(conflict_res.data) > 0:
                raise HTTPException(status_code=400, detail="رقم الموديل هذا مستخدم بالفعل لمنتج آخر، اختر رقماً فريداً")

        colors_data = json.loads(colors_json)
        deleted_image_ids = json.loads(deleted_image_ids_json)

        # 4. التحقق من عدم حذف أي لون أو مقاس مرتبط بمبيعات أو فواتير سابقة
        sold_items_res = await _execute_db_query(
            supabase_admin.table("order_items")
            .select("color_name, size_label")
            .eq("product_id", product_id)
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

        update_res = await _execute_db_query(
            supabase_admin.table("products")
            .update(prod_data)
            .eq("id", product_id)
        )

        if not update_res.data:
            raise HTTPException(status_code=500, detail="فشل تحديث بيانات المنتج الأساسية")

        qr_code_value = f"BAR-{model_number.upper()}"

        # 6. إدارة الصور القديمة (حذف الصور التي أزالها المستخدم + إعادة ختم الصور المتبقية إذا تغير الموديل)
        if deleted_image_ids:
            await _execute_db_query(
                supabase_admin.table("product_images")
                .delete()
                .in_("id", deleted_image_ids)
                .eq("product_id", product_id)
            )

        if model_number != old_model_number:
            existing_imgs = await _execute_db_query(
                supabase_admin.table("product_images")
                .select("*")
                .eq("product_id", product_id)
            )
            async with httpx.AsyncClient() as client:
                for img_rec in (existing_imgs.data or []):
                    try:
                        res_img = await client.get(img_rec["image_url"])
                        if res_img.status_code == 200:
                            new_bytes = await apply_qr_overlay(res_img.content, qr_code_value)
                            new_path = f"products/{product_id}/updated_{os.urandom(4).hex()}.jpg"
                            await run_in_threadpool(
                                supabase_admin.storage.from_("product-images").upload,
                                new_path,
                                new_bytes,
                                file_options={"content-type": "image/jpeg"},
                            )
                            new_url = supabase_admin.storage.from_("product-images").get_public_url(new_path)
                            await _execute_db_query(
                                supabase_admin.table("product_images")
                                .update({"image_url": new_url})
                                .eq("id", img_rec["id"])
                            )
                    except Exception as img_err:
                        print("⚠️ تحذير أثناء تحديث باركود صورة قديمة:", repr(img_err))

        # 7. تحديث الألوان والمقاسات والكميات بأمان بعد اجتياز فحص المبيعات التاريخية
        old_colors_res = await _execute_db_query(
            supabase_admin.table("product_colors")
            .select("id")
            .eq("product_id", product_id)
        )
        for col in (old_colors_res.data or []):
            await _execute_db_query(
                supabase_admin.table("product_variants")
                .delete()
                .eq("color_id", col["id"])
            )
        await _execute_db_query(
            supabase_admin.table("product_colors")
            .delete()
            .eq("product_id", product_id)
        )

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

            color_res = await _execute_db_query(
                supabase_admin.table("product_colors").insert(color_insert_data)
            )

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

                    await _execute_db_query(
                        supabase_admin.table("product_variants").insert({
                            "color_id": color_id,
                            "size_label": size_label,
                            "stock_qty": qty
                        })
                    )

                # رفع صور الألوان الجديدة ودمج QR الموديل الحالي باستخدام الفهرس المطابق
                color_images = form.getlist(f"color_images_{index}")
                for img in color_images:
                    if hasattr(img, "filename") and img.filename:
                        image_bytes = await img.read()
                        processed_bytes = await apply_qr_overlay(image_bytes, qr_code_value)
                        file_name = f"col_{os.urandom(4).hex()}_{os.path.basename(img.filename)}"
                        file_path = f"products/{product_id}/colors/{color_id}/{file_name}"

                        await run_in_threadpool(
                            supabase_admin.storage.from_("product-images").upload,
                            file_path,
                            processed_bytes,
                            file_options={"content-type": "image/jpeg"},
                        )
                        public_url = supabase_admin.storage.from_("product-images").get_public_url(file_path)

                        await _execute_db_query(
                            supabase_admin.table("product_images").insert({
                                "product_id": product_id,
                                "color_id": color_id,
                                "image_url": public_url,
                                "image_type": "color"
                            })
                        )

        # 8. رفع الصور العامة الجديدة ودمج QR الموديل الحالي
        general_images = form.getlist("general_images")
        for img in general_images:
            if hasattr(img, "filename") and img.filename:
                image_bytes = await img.read()
                processed_bytes = await apply_qr_overlay(image_bytes, qr_code_value)
                file_name = f"gen_{os.urandom(4).hex()}_{os.path.basename(img.filename)}"
                file_path = f"products/{product_id}/general/{file_name}"

                await run_in_threadpool(
                    supabase_admin.storage.from_("product-images").upload,
                    file_path,
                    processed_bytes,
                    file_options={"content-type": "image/jpeg"},
                )
                public_url = supabase_admin.storage.from_("product-images").get_public_url(file_path)

                await _execute_db_query(
                    supabase_admin.table("product_images").insert({
                        "product_id": product_id,
                        "image_url": public_url,
                        "image_type": "general"
                    })
                )

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
def _get_or_create_central_quota(merchant_id: str):
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
def _validate_and_encode_scan_image(image_bytes: bytes):
    with Image.open(io.BytesIO(image_bytes)) as uploaded_image:
        image_format = uploaded_image.format
        uploaded_image.verify()

    image_mime_type = Image.MIME.get(image_format)
    if not image_mime_type or not image_mime_type.startswith("image/"):
        return image_mime_type, None
    return image_mime_type, base64.b64encode(image_bytes).decode("ascii")


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

    started_at = perf_counter()
    try:
        # 1. التحقق من حصة التاجر في القاعدة المركزية المنفصلة
        images_used, allowed_limit, is_subscribed = await run_in_threadpool(
            _get_or_create_central_quota,
            merchant_id,
        )
        print(f"Carton scan quota check: {perf_counter() - started_at:.2f}s")

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

        image_bytes = await file.read(MAX_SCAN_IMAGE_BYTES + 1)
        if len(image_bytes) > MAX_SCAN_IMAGE_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="حجم الصورة يتجاوز الحد المسموح (10 ميغابايت).",
            )

        try:
            image_mime_type, image_base64 = await run_in_threadpool(
                _validate_and_encode_scan_image,
                image_bytes,
            )
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
        image_data_url = f"data:{image_mime_type};base64,{image_base64}"
        model_started_at = perf_counter()
        response = await openai_client.responses.create(
            model="gpt-6-luna",
            input=[
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "input_text",
                            "text": (
                                "اقرأ ملصق كرتون الحذاء بعناية. رقم الموديل هو القيمة المطبوعة بجوار "
                                "ART NO أو ART.NO. أو ITEM NO أو ITEM.NO. أو MODEL أو STYLE أو "
                                "ARTICLE أو مسمى واضح آخر لرقم الموديل؛ انقل القيمة حرفياً بكل حروفها "
                                "وأرقامها وعلاماتها، مع التمييز بين الحروف والأرقام. "
                                "لا تستخدم الباركود أو المقاس أو رقم الكمية كرقم موديل. "
                                "قد يكون جدول الكميات مصفوفة: صف SIZE يحتوي المقاسات كرؤوس أعمدة، "
                                "وكل صف أسفله يبدأ باسم لون وتحت كل مقاس كمية ذلك اللون والمقاس. "
                                "اقرأ كل صف لون على حدة، وطابق موضع كل رقم كمية مع عمود المقاس فوقه، "
                                "حتى إذا كانت الأعمدة دون خطوط فاصلة. أنشئ variant لكل تقاطع مقاس "
                                "ولون تظهر فيه كمية؛ stock_qty هو الرقم في التقاطع وليس رقم المقاس "
                                "أو إجمالي QTY. لا تنشئ variant لخانة فارغة ولا تنسخ كميات صف لآخر. "
                                "ترجم أسماء الألوان إلى العربية، واستخدم size_label نصاً وstock_qty "
                                "عدداً صحيحاً. إذا ظهر المقاس لكن كميته غير مقروءة فاستخدم null للكمية. "
                                "لا تخمّن رقماً أو كمية غير مقروءة: استخدم null لرقم الموديل غير المؤكد "
                                "و[] عند عدم ظهور بيانات واضحة. "
                                "أعد JSON مطابقاً تماماً للمخطط المطلوب."
                            ),
                        },
                        {
                            "type": "input_image",
                            "image_url": image_data_url,
                            "detail": "high",
                        },
                    ],
                }
            ],
            text={
                "format": {
                    "type": "json_schema",
                    "name": "carton_product_details",
                    "strict": True,
                    "schema": {
                        "type": "object",
                        "properties": {
                            "model_number": {
                                "type": ["string", "null"],
                            },
                            "colors": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "color_name": {"type": "string"},
                                        "variants": {
                                            "type": "array",
                                            "items": {
                                                "type": "object",
                                                "properties": {
                                                    "size_label": {
                                                        "type": ["string", "null"],
                                                    },
                                                    "stock_qty": {
                                                        "type": ["integer", "null"],
                                                    },
                                                },
                                                "required": [
                                                    "size_label",
                                                    "stock_qty",
                                                ],
                                                "additionalProperties": False,
                                            },
                                        },
                                    },
                                    "required": ["color_name", "variants"],
                                    "additionalProperties": False,
                                },
                            },
                        },
                        "required": ["model_number", "colors"],
                        "additionalProperties": False,
                    },
                }
            },
        )
        print(f"Carton scan OpenAI request: {perf_counter() - model_started_at:.2f}s")

        # 4. تحديث العداد في القاعدة المركزية بزيادة 1
        new_used_count = images_used + 1
        await _execute_db_query(
            central_supabase.table("merchant_quotas")
            .update({
                "images_used": new_used_count,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            })
            .eq("merchant_id", merchant_id)
        )

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
    finally:
        print(f"Carton scan total: {perf_counter() - started_at:.2f}s")


# ==================== تشغيل الخادم ====================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
