from flask import Flask, render_template
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Length
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SECRET_KEY'] = 'MY SUPER SAVE KEY'

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql//root:4316@localhost/netflix_db'


# email validator extra but not now .. check docs

class UserForm(FlaskForm):
    name = StringField("Your name", validators=[DataRequired()],
                       render_kw={'autofocus': True, 'placeholder': 'Your name'})
    email = StringField("Your email", validators=[DataRequired()],
                        render_kw={'autofocus': True, 'placeholder': 'Your email'})
    password = PasswordField("Your password", validators=[DataRequired()],
                             render_kw={'autofocus': True, 'placeholder': 'Your password'})
    password_confirm = PasswordField("Your password again",
                                     validators=[EqualTo('password', message='Passwords must match')],
                                     render_kw={'autofocus': True, 'placeholder': 'Repeat the password'})
    submit = SubmitField('Submit')


@app.route('/')
def index():  # put application's code here
    return render_template('home.html')


@app.route('/login')
def login():
    return render_template('login.html')


@app.route('/register')
def register():
    form = UserForm()
    return render_template('register.html', form=form)


if __name__ == '__main__':
    app.run(debug=True)
