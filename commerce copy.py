import os
import base64
import datetime
from decimal import Decimal, InvalidOperation

import pymysql
import requests
from flask import Flask, jsonify, request,session
from requests.auth import HTTPBasicAuth
from werkzeug.security import check_password_hash, generate_password_hash


def load_environment_file(filename=".env"):
    """Load simple KEY=value pairs from .env without an extra dependency."""
    if not os.path.exists(filename):
        return
    with open(filename, encoding="utf-8") as environment_file:
        for line in environment_file:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


load_environment_file(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
app = Flask(__name__)

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "user": os.getenv("DB_USER", "root"),
    "password": os.getenv("DB_PASSWORD", ""),
    "database": os.getenv("DB_NAME", "e-commerce"),
    "cursorclass": pymysql.cursors.DictCursor,
    "autocommit": False,
}

MPESA_ENVIRONMENT = os.getenv("MPESA_ENVIRONMENT", "sandbox").lower()
MPESA_BASE_URL = (
    "https://api.safaricom.co.ke"
    if MPESA_ENVIRONMENT == "production"
    else "https://sandbox.safaricom.co.ke"
)
MPESA_CONSUMER_KEY = os.getenv("MPESA_CONSUMER_KEY")
MPESA_CONSUMER_SECRET = os.getenv("MPESA_CONSUMER_SECRET")
MPESA_SHORTCODE = os.getenv("MPESA_SHORTCODE")
MPESA_PASSKEY = os.getenv("MPESA_PASSKEY")
MPESA_CALLBACK_URL = os.getenv("MPESA_CALLBACK_URL")


def mpesa_config_error():
    required = {
        "MPESA_CONSUMER_KEY": MPESA_CONSUMER_KEY,
        "MPESA_CONSUMER_SECRET": MPESA_CONSUMER_SECRET,
        "MPESA_SHORTCODE": MPESA_SHORTCODE,
        "MPESA_PASSKEY": MPESA_PASSKEY,
        "MPESA_CALLBACK_URL": MPESA_CALLBACK_URL,
    }
    missing = [
        name
        for name, value in required.items()
        if not value
        or value.startswith("replace_with_")
        or "your-public-domain.example" in value
    ]
    if missing:
        return f"M-Pesa is not configured. Missing: {', '.join(missing)}"
    if not MPESA_CALLBACK_URL.startswith("https://"):
        return "MPESA_CALLBACK_URL must be a public HTTPS URL"
    return None


def normalize_mpesa_phone(phone):
    digits = "".join(char for char in str(phone) if char.isdigit())
    if digits.startswith("0") and len(digits) == 10:
        digits = "254" + digits[1:]
    elif digits.startswith("7") and len(digits) == 9:
        digits = "254" + digits
    if len(digits) != 12 or not digits.startswith("2547"):
        return None
    return digits


def get_mpesa_access_token():
    response = requests.get(
        f"{MPESA_BASE_URL}/oauth/v1/generate?grant_type=client_credentials",
        auth=HTTPBasicAuth(MPESA_CONSUMER_KEY, MPESA_CONSUMER_SECRET),
        timeout=20,
    )
    response.raise_for_status()
    token = response.json().get("access_token")
    if not token:
        raise ValueError("M-Pesa did not return an access token")
    return token


def get_db_connection():
    return pymysql.connect(**DB_CONFIG)


def json_ready(value):
    if isinstance(value, Decimal):
        return float(value)
    return value


def serialize_row(row):
    return {key: json_ready(value) for key, value in row.items()}


def fetch_one(sql, params=None):
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(sql, params or ())
            row = cursor.fetchone()
            return serialize_row(row) if row else None
    finally:
        connection.close()


def fetch_all(sql, params=None):
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(sql, params or ())
            return [serialize_row(row) for row in cursor.fetchall()]
    finally:
        connection.close()


def require_fields(data, fields):
    missing = [field for field in fields if data.get(field) in (None, "")]
    if missing:
        return jsonify({"error": f"Missing required field(s): {', '.join(missing)}"}), 400
    return None


@app.errorhandler(pymysql.MySQLError)
def handle_mysql_error(error):
    return jsonify({"error": "Database error", "details": str(error)}), 500


@app.errorhandler(404)
def handle_not_found(_error):
    return jsonify({"error": "Not found"}), 404


@app.get("/")
def home():
    return jsonify(
        {
            "message": "E-commerce API is running",
            "endpoints": [
                "/users",
                "/login",
                "/products",
                "/products/<id>",
                "/products/<id>/variants",
                "/orders",
                "/orders/<id>",
            ],
        }
    )


@app.post("/users")
def create_user():
    data = request.get_json(silent=True) or {}
    validation_error = require_fields(data, ["name", "email", "password"])
    if validation_error:
        return validation_error

    role = data.get("role", "customer")
    if role not in ("customer", "admin"):
        return jsonify({"error": "Role must be 'customer' or 'admin'"}), 400

    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO users (name, email, password_hash, role)
                VALUES (%s, %s, %s, %s)
                """,
                (
                    data["name"],
                    data["email"],
                    generate_password_hash(data["password"]),
                    role,
                ),
            )
            user_id = cursor.lastrowid
        connection.commit()
    except pymysql.err.IntegrityError:
        connection.rollback()
        return jsonify({"error": "Email already exists"}), 409
    finally:
        connection.close()

    return jsonify(fetch_one("SELECT id, name, email, role FROM users WHERE id = %s", (user_id,))), 201


@app.post("/login")
def login_user():
    data = request.get_json(silent=True) or {}
    validation_error = require_fields(data, ["email", "password"])
    if validation_error:
        return validation_error

    user = fetch_one(
        "SELECT id, name, email, password_hash, role FROM users WHERE email = %s",
        (data["email"],),
    )
    if not user or not check_password_hash(user["password_hash"], data["password"]):
        return jsonify({"error": "Invalid email or password"}), 401

    user.pop("password_hash")
    return jsonify({"message": "Login successful", "user": user})


@app.get("/users")
def get_users():
    users = fetch_all("SELECT id, name, email, role FROM users ORDER BY id DESC")
    return jsonify(users)


@app.get("/users/<int:user_id>")
def get_user(user_id):
    user = fetch_one("SELECT id, name, email, role FROM users WHERE id = %s", (user_id,))
    if not user:
        return jsonify({"error": "user not found"}), 404
    return jsonify(user)


@app.post("/products")
def create_product():
    data = request.get_json(silent=True) or {}
    validation_error = require_fields(data, ["title", "price", "category", "image_url"])
    if validation_error:
        return validation_error

    if data["category"] not in ("books", "apparel"):
        return jsonify({"error": "Category must be 'books' or 'apparel'"}), 400

    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO products (title, description, price, category, image_url)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (
                    data["title"],
                    data.get("description"),
                    data["price"],
                    data["category"],
                    data["image_url"],
                ),
            )
            product_id = cursor.lastrowid
        connection.commit()
    finally:
        connection.close()

    return jsonify(fetch_one("SELECT * FROM products WHERE id = %s", (product_id,))), 201


@app.get("/products")
def get_products():
    category = request.args.get("category")
    search = request.args.get("search")

    filters = []
    params = []
    if category:
        filters.append("category = %s")
        params.append(category)
    if search:
        filters.append("(title LIKE %s OR description LIKE %s)")
        params.extend([f"%{search}%", f"%{search}%"])

    where_clause = f"WHERE {' AND '.join(filters)}" if filters else ""
    products = fetch_all(f"SELECT * FROM products {where_clause} ORDER BY id DESC", params)
    return jsonify(products)


@app.get("/products/<int:product_id>")
def get_product(product_id):
    product = fetch_one("SELECT * FROM products WHERE id = %s", (product_id,))
    if not product:
        return jsonify({"error": "Product not found"}), 404

    product["variants"] = fetch_all(
        "SELECT * FROM product_variants WHERE product_id = %s ORDER BY id",
        (product_id,),
    )
    return jsonify(product)


@app.put("/products/<int:product_id>")
def update_product(product_id):
    data = request.get_json(silent=True) or {}
    allowed_fields = ["title", "description", "price", "category", "image_url"]
    updates = []
    params = []

    if data.get("category") and data["category"] not in ("books", "apparel"):
        return jsonify({"error": "Category must be 'books' or 'apparel'"}), 400

    for field in allowed_fields:
        if field in data:
            updates.append(f"{field} = %s")
            params.append(data[field])

    if not updates:
        return jsonify({"error": "No valid fields provided"}), 400

    params.append(product_id)
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                f"UPDATE products SET {', '.join(updates)} WHERE id = %s",
                params,
            )
            if cursor.rowcount == 0:
                connection.rollback()
                return jsonify({"error": "Product not found"}), 404
        connection.commit()
    finally:
        connection.close()

    return jsonify(fetch_one("SELECT * FROM products WHERE id = %s", (product_id,)))


@app.delete("/products/<int:product_id>")
def delete_product(product_id):
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM products WHERE id = %s", (product_id,))
            if cursor.rowcount == 0:
                connection.rollback()
                return jsonify({"error": "Product not found"}), 404
        connection.commit()
    finally:
        connection.close()

    return jsonify({"message": "Product deleted"})


@app.post("/products/<int:product_id>/variants")
def create_product_variant(product_id):
    data = request.get_json(silent=True) or {}
    stock_quantity = data.get("stock_quantity", 0)

    if not fetch_one("SELECT id FROM products WHERE id = %s", (product_id,)):
        return jsonify({"error": "Product not found"}), 404

    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO product_variants (product_id, size, color, stock_quantity)
                VALUES (%s, %s, %s, %s)
                """,
                (product_id, data.get("size"), data.get("color"), stock_quantity),
            )
            variant_id = cursor.lastrowid
        connection.commit()
    finally:
        connection.close()

    return jsonify(fetch_one("SELECT * FROM product_variants WHERE id = %s", (variant_id,))), 201


@app.get("/products/<int:product_id>/variants")
def get_product_variants(product_id):
    variants = fetch_all(
        "SELECT * FROM product_variants WHERE product_id = %s ORDER BY id",
        (product_id,),
    )
    return jsonify(variants)


@app.put("/variants/<int:variant_id>")
def update_product_variant(variant_id):
    data = request.get_json(silent=True) or {}
    allowed_fields = ["size", "color", "stock_quantity"]
    updates = []
    params = []

    for field in allowed_fields:
        if field in data:
            updates.append(f"{field} = %s")
            params.append(data[field])

    if not updates:
        return jsonify({"error": "No valid fields provided"}), 400

    params.append(variant_id)
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                f"UPDATE product_variants SET {', '.join(updates)} WHERE id = %s",
                params,
            )
            if cursor.rowcount == 0:
                connection.rollback()
                return jsonify({"error": "Variant not found"}), 404
        connection.commit()
    finally:
        connection.close()

    return jsonify(fetch_one("SELECT * FROM product_variants WHERE id = %s", (variant_id,)))


@app.delete("/variants/<int:variant_id>")
def delete_product_variant(variant_id):
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM product_variants WHERE id = %s", (variant_id,))
            if cursor.rowcount == 0:
                connection.rollback()
                return jsonify({"error": "Variant not found"}), 404
        connection.commit()
    finally:
        connection.close()

    return jsonify({"message": "Variant deleted"})


@app.post("/orders")
def create_order():
    data = request.get_json(silent=True) or {}
    validation_error = require_fields(data, ["user_id", "items"])
    if validation_error:
        return validation_error

    if not isinstance(data["items"], list) or not data["items"]:
        return jsonify({"error": "Items must be a non-empty list"}), 400

    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT id FROM users WHERE id = %s", (data["user_id"],))
            if not cursor.fetchone():
                connection.rollback()
                return jsonify({"error": "User not found"}), 404

            product_ids = [item.get("product_id") for item in data["items"]]
            if any(product_id is None for product_id in product_ids):
                connection.rollback()
                return jsonify({"error": "Each item must include product_id"}), 400

            placeholders = ", ".join(["%s"] * len(product_ids))
            cursor.execute(
                f"SELECT id, price FROM products WHERE id IN ({placeholders})",
                product_ids,
            )
            products = {product["id"]: product for product in cursor.fetchall()}

            total_amount = Decimal("0.00")
            order_items = []
            for item in data["items"]:
                product = products.get(item["product_id"])
                quantity = int(item.get("quantity", 1))
                if not product:
                    connection.rollback()
                    return jsonify({"error": f"Product {item['product_id']} not found"}), 404
                if quantity <= 0:
                    connection.rollback()
                    return jsonify({"error": "Quantity must be greater than 0"}), 400

                price = product["price"]
                total_amount += price * quantity
                order_items.append((item["product_id"], quantity, price))

            cursor.execute(
                """
                INSERT INTO orders (user_id, total_amount, status)
                VALUES (%s, %s, %s)
                """,
                (data["user_id"], total_amount, data.get("status", "pending")),
            )
            order_id = cursor.lastrowid

            for product_id, quantity, price in order_items:
                cursor.execute(
                    """
                    INSERT INTO order_items
                    (order_id, product_id, quantity, price_at_purchase)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (order_id, product_id, quantity, price),
                )

        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()

    return jsonify(get_order_payload(order_id)), 201


def get_order_payload(order_id):
    order = fetch_one("SELECT * FROM orders WHERE id = %s", (order_id,))
    if not order:
        return None

    order["items"] = fetch_all(
        """
        SELECT oi.id, oi.order_id, oi.product_id, p.title, oi.quantity, oi.price_at_purchase
        FROM order_items oi
        JOIN products p ON p.id = oi.product_id
        WHERE oi.order_id = %s
        ORDER BY oi.id
        """,
        (order_id,),
    )
    return order


@app.get("/orders")
def get_orders():
    orders = fetch_all("SELECT * FROM orders ORDER BY id DESC")
    return jsonify(orders)


@app.get("/orders/<int:order_id>")
def get_order(order_id):
    order = get_order_payload(order_id)
    if not order:
        return jsonify({"error": "Order not found"}), 404
    return jsonify(order)


@app.post("/api/mpesa_payment")
def mpesa_payment():
    """Initiate an M-Pesa STK Push using the total of an existing order."""
    config_error = mpesa_config_error()
    if config_error:
        return jsonify({"error": config_error}), 503

    data = request.get_json(silent=True) or request.form.to_dict()
    validation_error = require_fields(data, ["order_id", "phone"])
    if validation_error:
        return validation_error

    try:
        order_id = int(data["order_id"])
    except (TypeError, ValueError):
        return jsonify({"error": "order_id must be an integer"}), 400

    order = fetch_one("SELECT id, total_amount, status FROM orders WHERE id = %s", (order_id,))
    if not order:
        return jsonify({"error": "Order not found"}), 404
    if order["status"] == "paid":
        return jsonify({"error": "Order has already been paid"}), 409

    try:
        amount = Decimal(str(order["total_amount"]))
    except (InvalidOperation, TypeError, ValueError):
        return jsonify({"error": "Order has an invalid total amount"}), 500
    if amount <= 0 or amount != amount.to_integral_value():
        return jsonify({"error": "Order total must be a positive whole number of KES"}), 400

    phone = normalize_mpesa_phone(data["phone"])
    if not phone:
        return jsonify({"error": "phone must be a valid Kenyan Safaricom number"}), 400

    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S")
    password = base64.b64encode(
        f"{MPESA_SHORTCODE}{MPESA_PASSKEY}{timestamp}".encode("utf-8")
    ).decode("utf-8")
    payload = {
        "BusinessShortCode": MPESA_SHORTCODE,
        "Password": password,
        "Timestamp": timestamp,
        "TransactionType": "CustomerPayBillOnline",
        "Amount": int(amount),
        "PartyA": phone,
        "PartyB": MPESA_SHORTCODE,
        "PhoneNumber": phone,
        "CallBackURL": MPESA_CALLBACK_URL,
        "AccountReference": f"ORDER-{order_id}",
        "TransactionDesc": f"Order {order_id}",
    }

    try:
        access_token = get_mpesa_access_token()
        response = requests.post(
            f"{MPESA_BASE_URL}/mpesa/stkpush/v1/processrequest",
            json=payload,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=30,
        )
        response_data = response.json()
        response.raise_for_status()
    except (requests.RequestException, ValueError) as error:
        return jsonify({"error": "Unable to initiate M-Pesa payment", "details": str(error)}), 502

    if response_data.get("ResponseCode") != "0":
        return jsonify({"error": "M-Pesa rejected the payment request", "mpesa": response_data}), 502

    return jsonify({
        "message": "STK Push sent. Complete the payment on your phone.",
        "order_id": order_id,
        "amount": int(amount),
        "checkout_request_id": response_data.get("CheckoutRequestID"),
        "customer_message": response_data.get("CustomerMessage"),
    }), 202


@app.post("/api/mpesa/callback")
def mpesa_callback():
    """Receive the asynchronous STK Push result from Safaricom."""
    data = request.get_json(silent=True) or {}
    callback = data.get("Body", {}).get("stkCallback", {})
    checkout_request_id = callback.get("CheckoutRequestID")
    if not checkout_request_id:
        return jsonify({"ResultCode": 1, "ResultDesc": "Invalid callback"}), 400

    result_code = callback.get("ResultCode")
    metadata = {
        item.get("Name"): item.get("Value")
        for item in callback.get("CallbackMetadata", {}).get("Item", [])
    }
    status = "paid" if str(result_code) == "0" else "failed"
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT order_id FROM mpesa_payments WHERE checkout_request_id = %s",
                (checkout_request_id,),
            )
            payment = cursor.fetchone()
            if payment:
                cursor.execute(
                    """
                    UPDATE mpesa_payments
                    SET status = %s, result_code = %s, result_desc = %s,
                        receipt_number = %s, paid_at = %s
                    WHERE checkout_request_id = %s
                    """,
                    (status, result_code, callback.get("ResultDesc"), metadata.get("MpesaReceiptNumber"), metadata.get("TransactionDate"), checkout_request_id),
                )
                if status == "paid":
                    cursor.execute("UPDATE orders SET status = 'paid' WHERE id = %s", (payment["order_id"],))
        connection.commit()
    finally:
        connection.close()

    # Safaricom expects a successful acknowledgement even if this callback is repeated.
    return jsonify({"ResultCode": 0, "ResultDesc": "Accepted"})


@app.get("/orders/<int:order_id>/mpesa-payment")
def get_mpesa_payment(order_id):
    payment = fetch_one(
        "SELECT * FROM mpesa_payments WHERE order_id = %s ORDER BY id DESC LIMIT 1",
        (order_id,),
    )
    if not payment:
        return jsonify({"error": "No M-Pesa payment found for this order"}), 404
    return jsonify(payment)


@app.patch("/orders/<int:order_id>/status")
def update_order_status(order_id):
    data = request.get_json(silent=True) or {}
    validation_error = require_fields(data, ["status"])
    if validation_error:
        return validation_error

    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE orders SET status = %s WHERE id = %s",
                (data["status"], order_id),
            )
            if cursor.rowcount == 0:
                connection.rollback()
                return jsonify({"error": "Order not found"}), 404
        connection.commit()
    finally:
        connection.close()

    return jsonify(get_order_payload(order_id))


@app.get("/order-items")
def get_order_items():
    order_items = fetch_all("SELECT * FROM order_items ORDER BY id DESC")
    return jsonify(order_items)

@app.route('/api/cart', methods=['GET'])
def get_cart():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized access. Please log in."}), 401
    
    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        query = """
            SELECT c.id, c.product_id, c.quantity, p.name, p.price, p.image_url 
            FROM cart c 
            JOIN products p ON c.product_id = p.id 
            WHERE c.user_id = %s
        """
        cursor.execute(query, (user_id,))
        cart_items = cursor.fetchall()
        return jsonify(cart_items), 200
    except Exception as e:
        return jsonify({"error": "An internal error occurred."}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/cart', methods=['POST'])
def add_to_cart():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized access. Please log in."}), 401
        
    data = request.get_json()
    product_id = data.get('product_id')
    quantity = data.get('quantity', 1)

    if not product_id:
        return jsonify({"error": "Product ID is required."}), 400

    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT id, quantity FROM cart WHERE user_id = %s AND product_id = %s", (user_id, product_id))
        existing_item = cursor.fetchone()

        if existing_item:
            new_quantity = existing_item['quantity'] + int(quantity)
            cursor.execute("UPDATE cart SET quantity = %s WHERE id = %s", (new_quantity, existing_item['id']))
        else:
            cursor.execute("INSERT INTO cart (user_id, product_id, quantity) VALUES (%s, %s, %s)", (user_id, product_id, quantity))
        
        conn.commit()
        return jsonify({"message": "Item added to cart successfully."}), 201
    except Exception as e:
        conn.rollback()
        return jsonify({"error": "Failed to add item to cart."}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/cart/<int:item_id>', methods=['DELETE'])
def remove_from_cart(item_id):
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized access."}), 401

    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("DELETE FROM cart WHERE id = %s AND user_id = %s", (item_id, user_id))
        conn.commit()
        
        if cursor.rowcount == 0:
            return jsonify({"error": "Item not found or unauthorized."}), 404
            
        return jsonify({"message": "Item removed from cart."}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({"error": "Failed to remove item."}), 500
    finally:
        cursor.close()
        conn.close()


# ==================== WISHLIST ENDPOINTS ====================

@app.route('/api/wishlist', methods=['GET'])
def get_wishlist():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized access."}), 401

    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        query = """
            SELECT w.id, w.product_id, p.name, p.price, p.image_url 
            FROM wishlist w 
            JOIN products p ON w.product_id = p.id 
            WHERE w.user_id = %s
        """
        cursor.execute(query, (user_id,))
        wishlist_items = cursor.fetchall()
        return jsonify(wishlist_items), 200
    except Exception as e:
        return jsonify({"error": "An internal error occurred."}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/wishlist', methods=['POST'])
def toggle_wishlist():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized access."}), 401

    data = request.get_json()
    product_id = data.get('product_id')

    if not product_id:
        return jsonify({"error": "Product ID is required."}), 400

    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT id FROM wishlist WHERE user_id = %s AND product_id = %s", (user_id, product_id))
        existing = cursor.fetchone()

        if existing:
            cursor.execute("DELETE FROM wishlist WHERE id = %s", (existing['id'],))
            conn.commit()
            return jsonify({"message": "Removed from wishlist", "status": "removed"}), 200
        else:
            cursor.execute("INSERT INTO wishlist (user_id, product_id) VALUES (%s, %s)", (user_id, product_id))
            conn.commit()
            return jsonify({"message": "Added to wishlist", "status": "added"}), 201
    except Exception as e:
        conn.rollback()
        return jsonify({"error": "Failed to update wishlist."}), 500
    finally:
        cursor.close()
        conn.close()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
