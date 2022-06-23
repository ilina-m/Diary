import email
from enum import unique
from hashlib import sha256
from msilib.schema import tables
from tabnanny import check
from tokenize import String
from flask import Flask, redirect, render_template, url_for
from flask_bootstrap import Bootstrap
import flask_login
from flask_wtf import FlaskForm, form
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
import email_validator
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_manager, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = "idk"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app) 
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(80))
    prompts = db.relationship('Prompts', backref='user')

class Prompts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(20), unique=True)
    content = db.Column(db.String(10000), unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

@login_manager.user_loader
def load_user(userid):
    return User.query.get(int(userid))

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15) ])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80) ])
    remember = BooleanField('Remember Me')

class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50) ])
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15) ])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80) ])
    
class NewPromptForm(FlaskForm):
    title = StringField('Title', validators=[InputRequired(), Length(max=20)])
    text = StringField('Text', validators=[InputRequired(), Length(max=20000)])

@app.route('/')
@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))
        return '<p1>Invalid username or password</p1>'
        
    return render_template('login.html', form=form)

@app.route('/signup', methods=["GET", "POST"])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        
        return redirect(url_for('dashboard'))
        
    return render_template('signup.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)

@app.route('/newprompt', methods=["GET", "POST"])
@login_required
def newprompt():
    form = NewPromptForm()
    theuser = flask_login.current_user.id

    if form.is_submitted():
        new_prompt = Prompts(title=form.title.data, content=form.text.data, user_id=theuser)
        db.session.add(new_prompt)
        db.session.commit()

    return render_template('newprompt.html', form=form)

@app.route('/view', methods=["GET", "POST"])
@login_required
def view():
    theuser = flask_login.current_user.id
    myPrompts = Prompts.query.filter_by(user_id = theuser)
    return render_template('view.html', myPrompts = myPrompts)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)