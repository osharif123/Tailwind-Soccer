from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user
from flaskext.mysql import MySQL
from wtforms import Form, StringField, PasswordField, validators

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this!

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# MySQL setup
mysql = MySQL()
app.config['MYSQL_DATABASE_USER'] = 'u390839445_Omar'
app.config['MYSQL_DATABASE_PASSWORD'] = 'Bismillah123!'
app.config['MYSQL_DATABASE_DB'] = 'u390839445_Sharif_users'
app.config['MYSQL_DATABASE_HOST'] = 'srv959.hstgr.io'
mysql.init_app(app)

class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    conn = None
    cursor = None
    try:
        conn = mysql.connect()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
        data = cursor.fetchone()
        if data is None:
            return None
        return User(data[0])  # assuming id is at index 0
    except Exception as e:
        print(e)
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

class LoginForm(Form):
    email = StringField('Email', [validators.Length(min=6, max=50), validators.Email()])
    password = PasswordField('Password', [validators.InputRequired()])

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        email = form.email.data
        password = form.password.data

        conn = None
        cursor = None
        try:
            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE email = %s AND password = %s', (email, password,))
            data = cursor.fetchone()

            if data is None:
                flash('Invalid email or password', 'danger')
                return render_template('login.html', form=form)
            else:
                user = User(data[0])  # assuming id is at index 0
                login_user(user)
                return redirect(url_for('home'))
        except Exception as e:
            print(e)
            flash('An error occurred during login. Please try again.', 'danger')
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    
    return render_template('login.html', form=form)


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')

