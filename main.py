import os
import json
import io
from typing import Optional

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


load_dotenv()

app = FastAPI(title="Auth API with Supabase")


# ==================== تهيئة اتصال Supabase ====================

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

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
        user_response = supabase.auth.get_user(token)

        if not user_response or not user_response.user:
            raise HTTPException(
                status_code=401,
                detail="لم يرجع Supabase مستخدمًا صالحًا"
            )

        return str(user_response.user.id)

    except HTTPException:
        raise

    except Exception as e:
        print("AUTH VERIFICATION ERROR:", repr(e))

        raise HTTPException(
            status_code=401,
            detail=f"فشل التحقق من التوكن: {type(e).__name__}"
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

            color_res = supabase.table("product_colors").insert({
                "product_id": product_id,
                "color_name": str(color_name).strip(),
                "color_code": color_item.get("color_code")
            }).execute()

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

                color_images = form.getlist(
                    f"color_images_{index}"
                )

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

    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="حدث خطأ أثناء حفظ المنتج أو صوره"
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
    """
    دالة مساعدة لإرسال رسائل نصية عبر WhatsApp Cloud API
    """
    if not WHATSAPP_TOKEN or not PHONE_NUMBER_ID:
        print("تنبيه: لم يتم إعداد WHATSAPP_TOKEN أو PHONE_NUMBER_ID في متغيرات البيئة.")
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
            print(f"WhatsApp API response status: {res.status_code}")
            return res.status_code == 200
        except Exception as e:
            print("Error sending WhatsApp message:", repr(e))
            return False


# ==================== WhatsApp Webhook Routes ====================

@app.get("/webhook")
async def verify_whatsapp_webhook(request: Request):
    """
    مسار التحقق المطلوب من منصة Meta لربط الـ Webhook
    """
    mode = request.query_params.get("hub.mode")
    token = request.query_params.get("hub.verify_token")
    challenge = request.query_params.get("hub.challenge")

    if mode and token:
        if mode == "subscribe" and token == VERIFY_TOKEN:
            return Response(content=challenge, media_type="text/plain")
        raise HTTPException(status_code=403, detail="Verification token mismatch")
    raise HTTPException(status_code=400, detail="Invalid request")


@app.post("/webhook")
async def receive_whatsapp_message(request: Request):
    """
    مسار استقبال ومعالجة رسائل واتساب الواردة
    """
    try:
        body = await request.json()
        print("Received WhatsApp Webhook event:", json.dumps(body, indent=2))

        entry = body.get("entry", [])
        for ent in entry:
            changes = ent.get("changes", [])
            for change in changes:
                value = change.get("value", {})
                messages = value.get("messages", [])

                if messages:
                    msg = messages[0]
                    sender_phone = msg.get("from")
                    msg_type = msg.get("type")

                    # الحالة الأولى: العميل أرسل صورة
                    if msg_type == "image":
                        image_data = msg.get("image", {})
                        caption = image_data.get("caption", "").strip()
                        media_id = image_data.get("id")

                        print(f"استلام صورة من {sender_phone}. النص المرفق: '{caption}' (Media ID: {media_id})")

                        reply_text = (
                            f"تم استلام صورة المنتج بنجاح! 📸\n"
                            f"جاري معالجة طلبك والتحقق من التوفر."
                        )
                        if caption:
                            reply_text += f"\nالتفاصيل المطلوبة: {caption}"

                        await send_whatsapp_message(sender_phone, reply_text)

                    # الحالة الثانية: العميل أرسل نصاً فقط (وليس صورة)
                    elif msg_type == "text":
                        text_body = msg.get("text", {}).get("body", "")
                        print(f"استلام نص فقط من {sender_phone}: {text_body}")

                        error_reply = (
                            "مرحباً بك في محلات فالنسيا! 🌸\n\n"
                            "لبدء الطلب أو الاستفسار، يرجى إرسال صورة للمنتج المطلوبة "
                            "على أن تكون إحدى منتجاتنا وتحتوي على الباركود الخاص بنا. "
                            "يمكنك كتابة المقاس أو اللون المطلوب كتعليق مرفق مع الصورة."
                        )
                        await send_whatsapp_message(sender_phone, error_reply)

        return {"status": "EVENT_RECEIVED"}

    except Exception as e:
        print("Error processing webhook:", repr(e))
        return {"status": "error"}


# ==================== تشغيل الخادم ====================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
