from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
import pandas as pd
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
from login import username, password

app = Flask(__name__)

# Configurations
app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{username}:{password}@localhost:5432/stanTechAi'
app.config['SECRET_KEY'] = 'your_secret_key'

db = SQLAlchemy(app)

# Models
class User(db.Model):
    __tablename__ = "Users"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Product(db.Model):
    __tablename__ = "Products"
    product_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    product_name = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    price = db.Column(db.Float, nullable=False)
    quantity_sold = db.Column(db.Integer, default=0)
    rating = db.Column(db.Float, nullable=True, default=None)
    review_count = db.Column(db.Integer, nullable=False, default=0)

with app.app_context():
    db.create_all()

# Authentication
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-token')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(username=data['username']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    existing_user = User.query.filter_by(username=data['username']).first()
    if existing_user:
        return jsonify({'message': 'Username already exists'}), 400
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(username=data['username'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({'message': 'Login failed!'}), 401
    token = jwt.encode({'username': user.username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
    return jsonify({'token': token}), 200

# Product Endpoints
@app.route('/products', methods=['GET'])
@token_required
def get_products(current_user):
    products = Product.query.all()
    product_list = [
        {
            "product_id": p.product_id,
            "product_name": p.product_name,
            "category": p.category,
            "price": p.price,
            "quantity_sold": p.quantity_sold,
            "rating": p.rating,
            "review_count": p.review_count
        }
        for p in products
    ]
    return jsonify({"products": product_list})

@app.route('/products/<int:product_id>', methods=['GET'])
@token_required
def get_product(current_user, product_id):
    product = Product.query.filter_by(product_id=product_id).first()
    if not product:
        return jsonify({'message': 'Product not found'}), 404
    return jsonify({
        "product_id": product.product_id,
        "product_name": product.product_name,
        "category": product.category,
        "price": product.price,
        "quantity_sold": product.quantity_sold,
        "rating": product.rating,
        "review_count": product.review_count
    }), 200

@app.route('/products/<int:product_id>', methods=['DELETE'])
@token_required
def delete_product(current_user, product_id):
    product = Product.query.filter_by(product_id=product_id).first()
    if not product:
        return jsonify({'message': 'Product not found'}), 404
    db.session.delete(product)
    db.session.commit()
    return jsonify({'message': f'Product (id:{product_id}) deleted'}), 200

@app.route('/products/<int:product_id>', methods=['PUT'])
@token_required
def update_product(current_user, product_id):
    product = Product.query.filter_by(product_id=product_id).first()
    if not product:
        return jsonify({'message': 'Product not found'}), 404

    data = request.get_json()

    # Check that product_name and category don't contain more than 64 chars
    if 'product_name' in data and len(data['product_name']) > 64:
        return jsonify({'message': 'Product name cannot be more than 64 characters'}), 400
    if 'category' in data and len(data['category']) > 64:
        return jsonify({'message': 'Category cannot be more than 64 characters'}), 400

    # Check that price, quantity_sold, rating, and review_count are integers
    if 'price' in data and not isinstance(data['price'], float):
        return jsonify({'message': 'Price must be an integer'}), 400
    if 'quantity_sold' in data and not isinstance(data['quantity_sold'], int):
        return jsonify({'message': 'Quantity sold must be an integer'}), 400
    if 'rating' in data and not isinstance(data['rating'], float):
        return jsonify({'message': 'Rating must be an integer'}), 400
    if 'review_count' in data and not isinstance(data['review_count'], int):
        return jsonify({'message': 'Review count must be an integer'}), 400

    product.product_name = data.get('product_name', product.product_name)
    product.category = data.get('category', product.category)
    product.price = data.get('price', product.price)
    product.quantity_sold = data.get('quantity_sold', product.quantity_sold)
    product.rating = data.get('rating', product.rating)
    product.review_count = data.get('review_count', product.review_count)
    db.session.commit()
    return jsonify({'message': 'Product updated'}), 200

@app.route('/products', methods=['POST'])
@token_required
def create_product(current_user):
    data = request.get_json()
    required_fields = ['product_name', 'category', 'price', 'quantity_sold', 'rating', 'review_count']
    if not all(field in data for field in required_fields):
        return jsonify({'message': 'Missing required fields'}), 400

    # Check that product_name and category don't contain more than 64 chars
    if len(data['product_name']) > 64:
        return jsonify({'message': 'Product name cannot be more than 64 characters'}), 400
    if len(data['category']) > 64:
        return jsonify({'message': 'Category cannot be more than 64 characters'}), 400

    # Check that price is float, quantity_sold is integer, rating is float, and review_count is integer
    if not isinstance(data['price'], float):
        return jsonify({'message': 'Price must be an integer'}), 400
    if not isinstance(data['quantity_sold'], int):
        return jsonify({'message': 'Quantity sold must be an integer'}), 400
    if not isinstance(data['rating'], float):
        return jsonify({'message': 'Rating must be an integer'}), 400
    if not isinstance(data['review_count'], int):
        return jsonify({'message': 'Review count must be an integer'}), 400

    new_product = Product(
        product_name=data['product_name'],
        category=data['category'],
        price=data['price'],
        quantity_sold=data['quantity_sold'],
        rating=data['rating'],
        review_count=data['review_count']
    )
    db.session.add(new_product)
    db.session.commit()
    return jsonify({'message': 'Product created'}), 201

# Data Upload from CSV
def csv_to_table(csvfilepath):
    try:
        df = pd.read_csv(csvfilepath)

	# check for columns
        required_columns = ['product_name', 'category', 'price', 'quantity_sold', 'rating', 'review_count']
        if not all(col in df.columns for col in required_columns):
            raise ValueError(f"CSV file is missing required columns: {required_columns}")

        df.fillna({'price': df['price'].median(), 'quantity_sold': df['quantity_sold'].median(), 'rating': df['rating'].mean()}, inplace=True)
        df['price'] = pd.to_numeric(df['price'], errors='coerce').fillna(0)
        df['quantity_sold'] = pd.to_numeric(df['quantity_sold'], errors='coerce').fillna(0)
        df['rating'] = pd.to_numeric(df['rating'], errors='coerce').fillna(df['rating'].mean())

        with app.app_context():
            for _, row in df.iterrows():
                new_product = Product(
                    product_name=row['product_name'],
                    category=row['category'],
                    price=row['price'],
                    quantity_sold=row['quantity_sold'],
                    rating=row['rating'],
                    review_count=row['review_count']
                )
                db.session.add(new_product)
            db.session.commit()
        return 0
    except FileNotFoundError:
        print(f"ERROR: The file {csvfilepath} was not found")
        return 1

    # additional error handling
    except pd.errors.ParserError as e:
        print(f"ERROR: Error parsing CSV file: {e}")
        return None
    except Exception as e:
        print(f"ERROR: Unexpected error: {e}")
        return None

# Summary Report
@app.route('/summary', methods=['GET'])
@token_required
def summary_report(current_user):
    report = db.session.query(
        Product.category,
        db.func.sum(Product.price * Product.quantity_sold).label('total_revenue'),
        db.func.max(Product.quantity_sold).label('top_product_quantity_sold')
    ).group_by(Product.category).all()

    summary_data = []
    for row in report:
        top_product = Product.query.filter_by(category=row.category).order_by(Product.quantity_sold.desc()).first()
        summary_data.append({
            'category': row.category,
            'total_revenue': row.total_revenue,
            'top_product': top_product.product_name,
            'top_product_quantity_sold': row.top_product_quantity_sold
        })

    return jsonify(summary_data), 200

if __name__ == "__main__":
    app.run(debug=True)