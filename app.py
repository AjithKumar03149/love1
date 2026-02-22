import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ultimate_love_secret_key_999'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///love_portal.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email Configuration (Replace with real SMTP for production)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASS')

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)

# MODELS
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    memories = db.relationship('Memory', backref='author', lazy=True)

class Memory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    content = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(200), nullable=True) # URL or path
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ROUTES
@app.route("/")
@login_required
def home():
    return render_template("index.html")

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, email=email, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        
        # Add a default memory for the new user
        default_memory = Memory(title="Our First Secret", content="The moment we entered this secret space together...", user_id=user.id)
        db.session.add(default_memory)
        db.session.commit()
        
        flash('Account created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
            return render_template('login.html', error="Invalid credentials 🥺")
    return render_template("login.html")

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/memories")
@login_required
def memories():
    user_memories = Memory.query.filter_by(user_id=current_user.id).all()
    return render_template("memories.html", memories=user_memories)

@app.route("/api/add-memory", methods=['POST'])
@login_required
def add_memory():
    data = request.json
    title = data.get('title')
    content = data.get('content')
    image_url = data.get('image_url')
    
    if not title or not content:
        return jsonify({"success": False, "error": "Title and content are required"}), 400
        
    new_memory = Memory(
        title=title, 
        content=content, 
        image_url=image_url, 
        author=current_user
    )
    db.session.add(new_memory)
    db.session.commit()
    
    return jsonify({"success": True, "status": "Memory captured! ✨"})

@app.route("/api/send-yes", methods=['POST'])
@login_required
def send_yes():
    # Only try to send email if config is present
    if app.config['MAIL_USERNAME'] and app.config['MAIL_PASSWORD']:
        try:
            msg = Message('SHE SAID YES! ❤️',
                          sender=app.config['MAIL_USERNAME'],
                          recipients=[current_user.email])
            msg.body = f"Congratulations! Your partner {current_user.username} just clicked YES on your special proposal website! \n\nForever starts now."
            mail.send(msg)
            return jsonify({"status": "Email sent! 💌"})
        except Exception as e:
            return jsonify({"status": "Success, but email failed (check config)", "error": str(e)})
    return jsonify({"status": "Success! (Email not configured)"})

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
