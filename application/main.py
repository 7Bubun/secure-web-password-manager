from flask import Flask, redirect, render_template, request, session
from flask_wtf.csrf import CSRFProtect, CSRFError
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import os

from db_manager import DataBaseManager
from login_attempts_guard import LoginAttemptsGuard
from account import account
from password_management import pm
from shares_management import sm

app = Flask(__name__)
app.secret_key = PBKDF2(os.getenv('PM_SECRET_KEY'), salt=get_random_bytes(8), count=1234)
protected_app = CSRFProtect(app)
lag = LoginAttemptsGuard()

try:
    dbm = DataBaseManager()
except:
    print('Nie udało się połączyć z bazą danych.')
    exit(1)

app.register_blueprint(account, url_prefix='/account')
app.register_blueprint(pm, url_prefix='/password-management')
app.register_blueprint(sm, url_prefix='/shares-management')

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return display_message('Błąd tokenu CSRF', '/login')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/passwords')
def passwords():
    if not 'username' in session:
        return redirect('/login')

    user = session['username']
    passwords = dbm.get_users_passwords(user)
    shared_passwords = dbm.get_passwords_shared_to_user(user)

    return render_template(
        'passwords.html',
        user=session['username'],
        list_of_passwords=passwords,
        shared_passwords=shared_passwords
    )    

def display_message(message: str, link: str):
    return render_template('message.html', message=message, link=link)

if __name__ == '__main__':
    app.run()
