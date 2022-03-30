from flask import Flask, render_template, flash, url_for, redirect
from flask_login import UserMixin, LoginManager, login_required, login_user, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import EqualTo, InputRequired

app = Flask(__name__)
app.config['SECRET_KEY'] = 'MY SUPER SAVE KEY'

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:4316@localhost/netflix_db'

# Login functions

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
# handle flash of protected routes
login_manager.login_message = 'User needs to be logged in to view this page'
login_manager.login_message_category = 'error'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# email validator extra but not now ... check docs

class RegisterForm(FlaskForm):
    name = StringField("Your name", validators=[InputRequired()],
                       render_kw={'autofocus': True, 'placeholder': 'Your name'})
    email = StringField("Your email", validators=[InputRequired()],
                        render_kw={'autofocus': True, 'placeholder': 'Your email'})
    password = PasswordField("Your password", validators=[InputRequired()],
                             render_kw={'autofocus': True, 'placeholder': 'Your password'})
    password_confirm = PasswordField("Your password again",
                                     validators=[EqualTo('password', message='Passwords must match')],
                                     render_kw={'autofocus': True, 'placeholder': 'Repeat the password'})
    submit = SubmitField('Submit')


class LoginForm(FlaskForm):
    email = StringField("Your email", validators=[InputRequired()],
                        render_kw={'autofocus': True, 'placeholder': 'Your email'})
    password = PasswordField("Your password", validators=[InputRequired()],
                             render_kw={'autofocus': True, 'placeholder': 'Your password'})
    submit = SubmitField('Sign in')


db = SQLAlchemy(app)


class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password_hash = db.Column(db.String(150), nullable=False)

    def __init__(self, name, email, password_hash):
        self.name = name
        self.email = email
        self.password_hash = password_hash

    @property
    def password(self):
        raise AttributeError('Password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)


@app.route('/')
def index():  # put application's code here
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            # check hashed_pw
            if check_password_hash(user.password_hash, form.password.data):
                login_user(user)
                flash('You are now logged in', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Wrong password', 'error')
        else:
            flash('That user does not exist', 'error')
    return render_template('login.html', form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if current_user.is_authenticated:
        return redirect(url_for('dashboard')) #function it

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None:
            hashed_pw = generate_password_hash(form.password.data, 'sha256')
            user = User(name=form.name.data, email=form.email.data, password_hash=hashed_pw)
            db.session.add(user)
            db.session.commit()
            flash('Account created successfully! Sign in now!', 'success')
            return redirect(url_for('login'))
        else:
            flash('Email address is in use!', 'error')
            return render_template('register.html', form=form)

    return render_template('register.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'success')
    return redirect(url_for('login'))



if __name__ == '__main__':
    app.run(debug=True)

# from app import db
# db.create_all()
