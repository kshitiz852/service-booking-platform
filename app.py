from datetime import timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
app = Flask(__name__)
app.secret_key = "victor_secret_key_123"

# DATABASE CONFIG
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///victor.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id='PASTE_CLIENT_ID_HERE',
    client_secret='PASTE_SECRET_HERE',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)
# SESSION TIME
app.permanent_session_lifetime = timedelta(days=7)

db = SQLAlchemy(app)

# ADMIN CONSTANT
ADMIN_USERNAME = "victoradmin"
ADMIN_PASSWORD = "12345"

# ================= MODELS =================
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))
    role = db.Column(db.String(20), default="user")  # user/admin




class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    address = db.Column(db.String(200))
    service = db.Column(db.String(100))

    price = db.Column(db.Integer)

    status = db.Column(db.String(20), default="Pending")

class Lead(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100))
    message = db.Column(db.String(300))



# @app.route('/book', methods=['POST'])
# def book():
#     new_booking = Booking(
#         name=request.form['name'],
#         phone=request.form['phone'],
#         address=request.form['address'],
#         service=request.form['service']
#     )
#     db.session.add(new_booking)
#     db.session.commit()
#     flash("Service Booked!")
#     return redirect(url_for('services'))


@app.route('/complete/<int:id>')
def complete_booking(id):
    booking = Booking.query.get(id)
    booking.status = "Done"
    db.session.commit()
    return redirect(url_for('admin'))


@app.route('/google-login')
def google_login():
    return google.authorize_redirect(url_for('google_callback', _external=True))

@app.route('/google-callback')
def google_callback():
    token = google.authorize_access_token()
    user_info = token['userinfo']

    session['user'] = user_info['email']
    session['role'] = "user"

    return redirect(url_for('home'))





# ================= ADMIN AUTO CREATE =================
def create_admin():
    admin = User.query.filter_by(username=ADMIN_USERNAME).first()
    if not admin:
        hashed = generate_password_hash(ADMIN_PASSWORD)
        admin_user = User(
            username=ADMIN_USERNAME,
            password=hashed,
            role="admin"
        )
        db.session.add(admin_user)
        db.session.commit()
        print("Admin Created → victoradmin / 12345")

# ================= ROUTES =================

@app.route('/')
def home():
    return render_template('index.html')


services_data = [
    {"name": "AC Repair & Installation", "price": 499, "img": "ac.jpg"},
    {"name": "Electrician", "price": 299, "img": "electric.jpg"},
    {"name": "Plumbing", "price": 199, "img": "plumbing.jpg"},
    {"name": "Wall Painting", "price": 799, "img": "painting.jpg"},
    {"name": "Garden Maintenance", "price": 399, "img": "garden.jpg"},
    {"name": "Pest Control", "price": 599, "img": "pest.jpg"},
]




@app.route('/services')
def services():
    return render_template('services.html', services=services_data)


@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact', methods=['GET','POST'])
def contact():
    if request.method == 'POST':
        lead = Lead(
            name=request.form['name'],
            email=request.form['email'],
            message=request.form['message']
        )
        db.session.add(lead)
        db.session.commit()
        flash("Message Sent Successfully!")
        return redirect(url_for('contact'))

    return render_template('contact.html')

# ================= LOGIN =================
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session.permanent = True
            session['user'] = user.username
            session['role'] = user.role

            flash("Login Success")

            if user.role == "admin":
                return redirect(url_for('admin'))
            else:
                return redirect(url_for('home'))

        flash("Invalid Credentials")

    return render_template('login.html')

# ================= SIGNUP (CUSTOMER) =================
@app.route('/signup', methods=['GET','POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        existing = User.query.filter_by(username=username).first()
        if existing:
            flash("Username Already Exists")
            return redirect(url_for('signup'))

        hashed = generate_password_hash(password)
        new_user = User(username=username, password=hashed, role="user")
        db.session.add(new_user)
        db.session.commit()

        flash("Account Created. Please Login.")
        return redirect(url_for('login'))

    return render_template('signup.html')

# ================= ADMIN PANEL =================
# @app.route('/admin')
# def admin():
#     if 'user' not in session or session.get('role') != "admin":
#         return redirect(url_for('home'))

#     leads = Lead.query.all()
#     bookings = Booking.query.all()

#     return render_template('admin.html', leads=leads, bookings=bookings)

@app.route('/admin')
def admin():
    if 'user' not in session or session.get('role') != "admin":
        return redirect(url_for('home'))

    bookings = Booking.query.all()
    leads = Lead.query.all()
    bookings = Booking.query.all()
    pending = Booking.query.filter_by(status="Pending").count()
    done = Booking.query.filter_by(status="Done").count()

    return render_template(
        'admin.html',
        bookings=bookings,
        pending=pending,
        leads=leads,
        done=done
    )


@app.route('/book/<service>/<int:price>', methods=['GET','POST'])
def book_service(service, price):

    if request.method == 'POST':
        new_booking = Booking(
            name=request.form['name'],
            phone=request.form['phone'],
            address=request.form['address'],
            service=service,
            price=price   # SIRF EK BAAR
        )

        db.session.add(new_booking)
        db.session.commit()
        flash("Service Booked Successfully!")
        return redirect(url_for('home'))

    return render_template('booking.html', service=service, price=price)


# ================= LOGOUT =================
@app.route('/logout')
def logout():
    session.clear()
    flash("Logged Out")
    return redirect(url_for('home'))

# ================= MAIN =================
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_admin()
    app.run(debug=True)
