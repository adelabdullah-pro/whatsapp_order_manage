import os
import json
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



load_dotenv()

app = FastAPI(title="Auth API with Supabase")
# ==================== تخزين جلسات محادثات الواتساب المؤقتة ====================
USER_SESSIONS = {}

# ==================== تهيئة اتصال Supabase ====================

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
# عميل خاص يتخطى سياسات RLS للعمليات الخلفية بأمان
supabase_admin: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY or SUPABASE_KEY)
if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError(
        "يجب ضبط SUPABASE_URL و SUPABASE_KEY في ملف البيئة"
    )

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)


# ==================== إعدادات WhatsApp API ====================

VERIFY_TOKEN = os.getenv("VERIFY_TOKEN")
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
        
        # طباعة تشخيصية في الـ Logs للتأكد من نجاح المصادقة ومعرفة الـ ID المستخرج
        print("🔍 Auth Response Object:", user_response)

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
async def get_products():
    try:
        response = supabase.table("products").select("*").execute()

        return {
            "status": "success",
            "data": response.data
        }

    except Exception:
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

@app.get("/api/product-images")
async def get_product_images():
    try:
        response = (
            supabase.table("product_images")
            .select("*")
            .execute()
        )

        return {
            "status": "success",
            "data": response.data
        }

    except Exception:
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

    if mode and token:
        if mode == "subscribe" and token == VERIFY_TOKEN:
            return Response(content=challenge, media_type="text/plain")
        raise HTTPException(status_code=403, detail="Verification token mismatch")
    raise HTTPException(status_code=400, detail="Invalid request")


# ==================== دالة استقبال رسائل واتساب مع الذكاء والتصحيح الإملائي ====================
@app.post("/webhook")
async def receive_whatsapp_message(request: Request):
    try:
        body = await request.json()

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

                # معالجة أمر الإلغاء/التصفير العام في أي وقت
                if msg_type == "text":
                    incoming_text = msg.get("text", {}).get("body", "").strip()
                    
                    if incoming_text in ["إلغاء", "الغاء", "cancel", "reset", "البداية"]:
                        USER_SESSIONS.pop(sender_phone, None)
                        await send_whatsapp_message(
                            sender_phone, 
                            "🔄 تم إلغاء العملية الحالية وتصفير المحادثة.\nأرسل صورة جديدة للمنتج متى ما أردت البدء من جديد 🌸"
                        )
                        continue

                # جلب حالة الجلسة الحالية للعميل
                session = USER_SESSIONS.get(sender_phone, {"step": "IDLE"})

                # ----------------------------------------------------
                # الحالة 1: إرسال صورة (بداية المحادثة واستخراج الباركود)
                # ----------------------------------------------------
                if msg_type == "image":
                    image_data = msg.get("image", {})
                    media_id = image_data.get("id")

                    barcode_value = await download_and_decode_whatsapp_image(media_id)

                    if not barcode_value:
                        reply_text = (
                            "❌ عذراً، الصورة المرسلة لا تحتوي على باركود صالح.\n"
                            "الرجاء إرسال صورة منتج تحتوي على الباركود الخاص بالمحل لاستكمال الطلب."
                        )
                        await send_whatsapp_message(sender_phone, reply_text)
                    else:
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

                        # ----------------------------------------------------
                        # 🚨 التعديل الجديد هنا: التحقق هل المنتج نفد بالكامل من المخزون
                        # ----------------------------------------------------
                        all_colors = product.get("product_colors", [])
                        valid_colors = []
                        for c in all_colors:
                            has_stock = any(v.get("stock_qty", 0) > 0 for v in c.get("product_variants", []))
                            if has_stock:
                                valid_colors.append(c)

                        if len(valid_colors) == 0:
                            # البحث عن اسم العميل إن وجد لمخاطبته بلطف
                            existing_customer_res = (
                                supabase_admin.table("orders")
                                .select("customer_name")
                                .eq("customer_phone", sender_phone)
                                .not_.eq("customer_name", "عميل واتساب")
                                .limit(1)
                                .execute()
                            )
                            known_name = existing_customer_res.data[0].get("customer_name") if existing_customer_res.data else None
                            customer_title = f"يا *{known_name}*" if known_name else "عزيزنا العميل"

                            out_of_stock_msg = (
                                f"أهلاً بك {customer_title} 🌸\n"
                                f"يسعدنا جداً اهتمامك بـ (*{product['name']}*) في **فالنسيا**! ✨\n\n"
                                f"نود إبلاغك بأن هذا المنتج قد **نفد بالكامل حالياً** نظراً للإقبال اللطيف عليه 💎\n\n"
                                f"نعمل باستمرار على إعادة توفير تشكيلاتنا المميزة، ويمكنك إرسال صورة لمنتج آخر وسنكون سعداء جداً بخدمتك 🌺"
                            )
                            await send_whatsapp_message(sender_phone, out_of_stock_msg)
                            continue

                        # 🔍 التحقق هل العميل مسجل مسبقاً برقم هاتفه برقم طلب سابق
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

                        # 🧠 الذكاء الأول: إذا لم يتبقى إلا لون واحد متاح للمنتج
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

                # ----------------------------------------------------
                # الحالة 2: استقبال الرسائل النصية ومتابعة الخطوات
                # ----------------------------------------------------
                elif msg_type == "text":
                    incoming_text = msg.get("text", {}).get("body", "").strip()
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

                    # 🧠 تأكيد اللون الوحيد (نعم / لا)
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

                    # الخطوة أ: اختيار اللون مع دعم التصحيح الإملائي للأخطاء مثل "اححمر"
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
                        
                        # 🧠 الذكاء الثاني: إذا كان لهذا اللون مقاس واحد فقط متاح
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

                    # 🧠 تأكيد المقاس الوحيد (نعم / لا)
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

                    # الخطوة ب: اختيار المقاس مع دعم المطابقة الذكية للأخطاء الإملائية
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

                    # الخطوة ج: التحقق من الكمية المدخلة مقارنة بالمخزون
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

                    # الخطوة د: العنوان وحفظ الطلب الفوري وتحديث (خصم) المخزون في قاعدة البيانات
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

                            # 🔄 خصم الكمية المحجوزة تلقائياً من مخزون المتغيرات (stock_qty)
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

        return {"status": "EVENT_RECEIVED"}

    except Exception as e:
        print("❌ CRITICAL WEBHOOK ERROR:", repr(e))
        return {"status": "error", "details": str(e)}


# ==================== دالة تحميل وقراءة الباركود من صورة واتساب ====================
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

            # قراءة الباركود أو الـ QR Code مباشرة عبر OpenCV
            detector = cv2.QRCodeDetector()
            val, _, _ = detector.detectAndDecode(img_cv)
            
            if val:
                print(f"تم العثور على باركود: {val}")
                return val

            print("⚠️ لم يتم العثور على باركود في الصورة")
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

    
    
# 3. تحديث حالة الطلب وتسجيل الحركة في السجل
@app.put("/api/orders/{order_id}/status")
async def update_order_status(order_id: str, data: OrderStatusUpdate):
    try:
        # أخذ الحالة القديمة للطلب أولاً
        current_order = supabase.table("orders").select("status").eq("id", order_id).execute()
        if not current_order.data:
            raise HTTPException(status_code=404, detail="الطلب غير موجود")
            
        old_status = current_order.data[0]["status"]
        new_status = data.new_status
        
        # تجهيز حقول التحديث وتواريخ الحالات
        update_data = {"status": new_status, "updated_at": datetime.now(timezone.utc).isoformat()}        
        if new_status == "processing":
            update_data["confirmed_at"] = "now()"
        elif new_status == "shipping":
            update_data["shipped_at"] = "now()"
        elif new_status == "completed":
            update_data["delivered_at"] = "now()"
        elif new_status == "cancelled":
            update_data["cancelled_at"] = "now()"
            if data.cancellation_reason:
                update_data["cancellation_reason"] = data.cancellation_reason

        # تنفيذ التحديث في جدول orders
        supabase.table("orders").update(update_data).eq("id", order_id).execute()
        
        # تسجيل الحركة في جدول order_logs
        supabase.table("order_logs").insert({
            "order_id": order_id,
            "old_status": old_status,
            "new_status": new_status,
            "notes": data.notes or f"تم تغيير الحالة من {old_status} إلى {new_status}"
        }).execute()

        return {
            "status": "success",
            "message": f"تم تحديث حالة الطلب إلى ({new_status}) بنجاح",
            "old_status": old_status,
            "new_status": new_status
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"خطأ في تحديث حالة الطلب: {str(e)}")


# ==================== تشغيل الخادم ====================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
