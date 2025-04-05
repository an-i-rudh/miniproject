from sqlalchemy.exc import IntegrityError
from itsdangerous import SignatureExpired
from itsdangerous import URLSafeTimedSerializer
from flask import Flask, request, render_template, redirect, flash, url_for,session  
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired  
import random
from dotenv import load_dotenv
import os
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_bcrypt import Bcrypt
from flask_admin import AdminIndexView, expose

load_dotenv()

app = Flask(__name__)

app.secret_key = 'your_secret_key'

# Email Configuration 
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USE_TLS'] = False  
app.config['MAIL_USERNAME'] =os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD') 



mail = Mail(app)
s = URLSafeTimedSerializer(app.secret_key)  # Token generator

#configuring SQLalchemy to use mysql
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

#creating an object to model database tables
class User(db.Model):
    name = db.Column(db.String(80), primary_key=True, nullable=False)
    pass_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)  

class Bus(db.Model):
    sino = db.Column(db.Integer, primary_key=True, nullable=False,autoincrement=True)
    starting_point = db.Column(db.String(120), nullable=False)
    destination_point = db.Column(db.String(120), nullable=False)  
    starting_time = db.Column(db.Time, nullable=False)
    destination_time = db.Column(db.Time, nullable=False)

class Taxi(db.Model):
    sino = db.Column(db.Integer, primary_key=True, nullable=False,autoincrement=True)
    name = db.Column(db.String(150), nullable=False)
    model = db.Column(db.String(120), nullable=False)  
    rate = db.Column(db.Integer, nullable=False)
    contact = db.Column(db.String(15), nullable=False)  

class Auto(db.Model):
    sino = db.Column(db.Integer, primary_key=True, nullable=False,autoincrement=True)
    name = db.Column(db.String(150), nullable=False)
    contact = db.Column(db.String(15), nullable=False)  

class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    workfield = db.Column(db.String(100), nullable=False)
    contact = db.Column(db.String(15), nullable=False) 

    
# Announcement Model
class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())



#Admin section

# Admin Model
# Admin User Model
class AdminUser(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')
    
    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

@login_manager.user_loader
def load_user(user_id):
    return AdminUser.query.get(int(user_id))

# Custom Admin Dashboard View
class MyAdminIndexView(AdminIndexView):
    @expose('/')
    def index(self):
        if not current_user.is_authenticated:
            return redirect(url_for('admin_login'))
        return self.render('admin_home.html')

# Secure Model View for Flask-Admin
class AdminModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('admin_login'))

# Initialize Admin Panel with Custom Dashboard
admin = Admin(app, name='Admin Panel', template_mode='bootstrap3', index_view=MyAdminIndexView())
admin.add_view(AdminModelView(Bus, db.session))
admin.add_view(AdminModelView(Taxi, db.session))
admin.add_view(AdminModelView(Auto, db.session))
admin.add_view(AdminModelView(Service, db.session))
admin.add_view(AdminModelView(Announcement, db.session))

# Admin Login Route
@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = AdminUser.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('admin.index'))  # Redirect to custom admin home
    return render_template("admin_login.html")

# Admin Logout Route
@app.route('/admin_logout')
@login_required
def admin_logout():
    logout_user()
    return redirect(url_for('admin_login'))

#creating all the defined tables if it doesn't exist
with app.app_context():
    db.create_all()



# Home Page
@app.route("/")
def home():
    all_announcements = Announcement.query.order_by(Announcement.created_at.desc()).all()
    return render_template("index.html",announcements=all_announcements)


#Normal user authentication section

# Login Page
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username")
    password = request.form.get("password")

    if not username or not password:
        flash('Username and password are required.', 'danger')
        return render_template("login.html")

    user = User.query.filter_by(name=username).first()

    if user is None :
        flash('User Not Found. Please try again.', 'danger')
        return render_template("login.html")
    elif  password.strip() != user.pass_hash.strip():
        flash('Invalid Credentials. Please try again.', 'danger')
        return render_template("login.html")
    return render_template("index.html")


# Signup Page
@app.route("/signup", methods=['GET', 'POST'])
def signup():
    if request.method == "GET":
        return render_template("signup.html")

    username = request.form.get("username")
    password = request.form.get("password")
    Email = request.form.get("email")

    new_user = User(name=username, pass_hash=password,email=Email)

    try:
        db.session.add(new_user)
        db.session.commit()
        return render_template('index.html')
    except IntegrityError:
        db.session.rollback()
        flash("User Already Exists!",'danger')
        return render_template("signup.html")


#  Forgot Password Page
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        
        if not user:
            flash('Email not found.', 'danger')
            return redirect(url_for('forgot_password'))
        
        # Generate a 6-digit reset code
        reset_code = str(random.randint(100000, 999999))
        
        # Store the code in session (or a temporary database table)
        session['reset_code'] = reset_code
        session['reset_email'] = email
        
        # Send email with the code
        msg = Message('Password Reset Code', sender='your_email@gmail.com', recipients=[email])
        msg.body = f'Your password reset code is: {reset_code}'
        mail.send(msg)
        
        flash('Password reset code sent! Check your email.', 'success')
        return redirect(url_for('verify_reset_code'))
    
    return render_template('forgot_password.html')


# Verify Reset Code page
@app.route('/verify_reset_code', methods=['GET', 'POST'])
def verify_reset_code():
    if request.method == 'POST':
        entered_code = request.form['reset_code']
        if session.get('reset_code') == entered_code:
            flash('Code verified! Please set a new password.', 'success')
            
            # Generate a token using the email in the session
            email = session.get('reset_email')
            if not email:
                flash('Session expired. Please request a new reset code.', 'danger')
                return redirect(url_for('forgot_password'))
            
            token = s.dumps(email, salt='password-reset')  # Generate token with email
            return redirect(url_for('reset_password', token=token)) #sends encrypted email in token
        
        else:
            flash('Invalid code. Please try again.', 'danger')
            return redirect(url_for('verify_reset_code'))
    
    return render_template('verify_reset_code.html')


# Reset Password Page
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset', max_age=3600)  # 1-hour expiry,Decrypts the email from token and stores in email
    except SignatureExpired:
        flash('The token has expired. Please try again.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        users = User.query.filter_by(email=email).first()
        new_password = request.form['password']
        users.pass_hash = new_password
        db.session.commit()  
        flash('Password reset successful! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)#passes the token when initially rendering



#transport section


@app.route('/transport', methods = ['GET'])
def transport():
    return render_template('local_transport.html')


#page to display bus details
@app.route('/bus', methods = ['GET'])
def bus():
    buses = Bus.query.all()
    return render_template('bus.html',buses=buses)


#page to display taxi details   
@app.route('/taxi', methods = ['GET'])
def taxi():
    taxis = Taxi.query.all()
    return render_template('taxi.html',taxis=taxis)


#page to display auto details
@app.route('/auto', methods = ['GET'])
def auto():
    autos = Auto.query.all()
    return render_template('auto.html',autos=autos)


#service section


@app.route('/local_worckforce')
def local_workforce():
    return render_template('local_workforce.html')



@app.route('/service')
def service():
    workfield = request.args.get('workfield')
    services = Service.query.filter_by(workfield=workfield).all()
    return render_template('service.html', services=services)


#announcement section

@app.route('/announcements')
def announcements():
    all_announcements = Announcement.query.order_by(Announcement.created_at.desc()).all()
    return render_template('announcement.html', announcements=all_announcements)

#emergency route

@app.route('/emergency')
def emergency():
    return render_template('emergency.html')

#tourism route

@app.route('/tourism')
def tourism():
    return render_template('tourism.html')


#healthcare route

@app.route('/healthcare')
def healthcare():
    return render_template('healthcare.html')

#education section
@app.route('/education')
def education():
    return render_template('education.html')


#government school route
@app.route('/govschool')
def govschool():
    return render_template('govschool.html')

#aided school route
@app.route('/aidedschool')
def aidedchool():
    return render_template('aidedschool.html')

#unaided school route
@app.route('/unaidedschool')
def unaidedschool():
    return render_template('unaidedschool.html')


@app.route('/administrative')
def administrative():
     return render_template('administrative.html')

if __name__ == "__main__":
    app.run(debug=True)
