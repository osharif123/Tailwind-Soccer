import logging
import traceback
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify

from flask_mysqldb import MySQL, cursors
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Email
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
import MySQLdb
from MySQLdb import OperationalError
from datetime import timedelta, datetime


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=10)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# MySQL setup
app.config['MYSQL_HOST'] = 'srv959.hstgr.io'
app.config['MYSQL_USER'] = 'u390839445_Omar'
app.config['MYSQL_PASSWORD'] = 'Bismillah123!'
app.config['MYSQL_DB'] = 'u390839445_Sharif_users'
mysql = MySQL(app)

@app.route('/')
@login_required
def index():
    return render_template('index.html')

class User(UserMixin):
    def __init__(self, id, email, password, is_admin):
        self.id = id
        self.email = email
        self.password = password
        self.is_admin = is_admin

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])

class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    admin_key = StringField('Admin Key')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        app.logger.info('Form submitted')
        try:
            email = form.email.data
            password = form.password.data
            cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)  # Use a dictionary cursor
            cur.execute("SELECT * FROM users WHERE email = %s", [email])
            user = cur.fetchone()
            if user and check_password_hash(user['password'], password):
                user_object = User(user['id'], user['email'], user['password'], user['is_admin'])
                login_user(user_object)
                session['user_id'] = user['id']  # Store the user's ID in the session
                session.permanent = True
                return redirect(url_for('index'))
            else:
                flash('Login Unsuccessful. Please check your email and password', 'danger')
        except Exception as e:
            logging.error(traceback.format_exc())
            flash('An error occurred while logging in. Please try again later.', 'danger')
    return render_template('login.html', title='Login', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        try:
            email = form.email.data
            password = form.password.data
            admin_key = form.admin_key.data
            cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)  # Use a dictionary cursor
            cur.execute("SELECT * FROM users WHERE email = %s", [email])
            user = cur.fetchone()
            if user:
                flash('Email address already exists. Choose a different one.', 'danger')
                return redirect(url_for('register'))

            hashed_password = generate_password_hash(password, method='sha256')
            is_admin = admin_key == 'correct_admin_key'
            cur.execute("INSERT INTO users (email, password, is_admin) VALUES (%s, %s, %s)", (email, hashed_password, is_admin))
            mysql.connection.commit()
            flash('You have successfully registered!', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            logging.error(traceback.format_exc())
            flash('An error occurred while registering. Please try again later.', 'danger')
    return render_template('register.html', title='Register', form=form)

def get_current_user():
    try:
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)  
        cur.execute("SELECT * FROM users WHERE id = %s", [session['user_id']])
        user = cur.fetchone()
        return user
    except Exception as e:
        logging.error(traceback.format_exc())
        flash('An error occurred while getting the current user. Please try again later.', 'danger')

@app.route('/create_event', methods=['POST'])
@login_required
def create_event():
    user = get_current_user()
    if not user['is_admin']:
        flash('Sorry, are you Syria or are you trying to act like him', 'danger')

    location = request.form.get('location')
    day = request.form.get('day')
    time = request.form.get('time')
    
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM events WHERE location = %s AND day = %s AND time = %s", (location, day, time))
    event = cur.fetchone()

    if event:
        flash('Event with the same location, date and time already exists', 'danger')
    else:
        cur.execute("INSERT INTO events (location, day, time) VALUES (%s, %s, %s)", (location, day, time))
        mysql.connection.commit()
        flash('You have successfully created the event!', 'success')

    return redirect(url_for('index'))


@app.route('/latest_event', methods=['GET'])
def latest_event():
    try:
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute("SELECT id, location, day, TIME_FORMAT(time, '%H:%i') as time FROM events ORDER BY id DESC LIMIT 1")
        latest_event = cur.fetchone()

        if not latest_event:
            return jsonify({'error': 'No events found.'}), 404

        cur.execute("SELECT COUNT(*) as count FROM rsvps WHERE event_id = %s", [latest_event['id']])
        rsvp_count = cur.fetchone()['count']

        # format date in Python
        latest_event['day'] = latest_event['day'].strftime('%Y-%m-%d')

        return jsonify({'latest_event': latest_event, 'rsvp_count': rsvp_count})

    except Exception as e:
        return jsonify({'error': str(e)}), 500





@app.route('/rsvp', methods=['POST'])
@login_required
def rsvp():
    event_id = request.form.get('event_id')
    try:
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute("SELECT COUNT(*) as count FROM rsvps WHERE event_id = %s", [event_id])
        rsvp_count = cur.fetchone()['count']

        if rsvp_count >= 12:
            flash('Too late. We already have 12 people. Please do not show up.', 'danger')
            return redirect(url_for('index'))

        cur.execute("INSERT INTO rsvps (first_name, timestamp, event_id) VALUES (%s, NOW(), %s)", (session['user_id'], event_id))
        mysql.connection.commit()
        flash('Thanks, you\'re in!', 'success')
        return redirect(url_for('index'))

    except Exception as e:
        logging.error(traceback.format_exc())
        flash('An error occurred while registering. Please try again later.', 'danger')
        return redirect(url_for('index'))


@login_manager.user_loader
def load_user(user_id):
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)  # Use a dictionary cursor
    cur.execute("SELECT * FROM users WHERE id = %s", [user_id])
    user_db = cur.fetchone()
    if user_db:
        user = User(user_db['id'], user_db['email'], user_db['password'], user_db['is_admin'])
        return user
    return None


@app.errorhandler(500)
def handle_internal_error(error):
    logging.error(f"Server Error: {error}\n{traceback.format_exc()}")
    flash('An internal error occurred. Please try again later.', 'danger')
    return render_template('500.html'), 500

@app.errorhandler(404)
def handle_not_found_error(error):
    logging.error(f"Page Not Found: {error}\n{traceback.format_exc()}")
    flash('The page you requested could not be found.', 'danger')
    return render_template('404.html'), 404

@app.errorhandler(OperationalError)
def handle_db_error(err):
    logging.error(f"Database Error: {err}\n{traceback.format_exc()}")
    flash('A database error occurred. Please try again later.', 'danger')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)

