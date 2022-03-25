from flask import Flask, render_template, flash, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo, InputRequired

app = Flask(__name__)
app.config['SECRET_KEY'] = 'MY SUPER SAVE KEY'

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:4316@localhost/netflix_db'


# email validator extra but not now .. check docs

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


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key = True)
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
    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

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


if __name__ == '__main__':
    app.run(debug=True)

# from app import db
# db.create_all()