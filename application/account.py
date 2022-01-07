from flask import Blueprint, session, request, redirect, render_template
from Crypto.Random import get_random_bytes
from time import sleep

from main import dbm, lag, display_message
from config import Config

account = Blueprint('account', __name__, static_folder='static', template_folder='templates')

@account.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        if 'username' in session:
            return redirect('/passwords')
        return render_template('login.html')
    
    else:
        if not 'username' in request.form or not 'password' in request.form:
            return render_template('message.html', message='bad form', link='/login')

        sleep(0.7)
        username = request.form['username']
        password = request.form['password']

        lag.refresh_login_attempts()

        if not lag.verify_login_attempt(username):
            return render_template(
                'message.html',
                message='Konto tymczasowo zablokowane z powodu zbyt dużej liczby prób logowania.',
                link='/login'
            )

        for char in username + password:
            if not char in Config.get_accepted_characters():
                return render_template('message.html', message='Niedozwolone znaki!', link='/login') # TMP message

        try:
            dbm.verify_user(username, password)
            session['username'] = username            
            return redirect('/passwords')
        except Exception:
            lag.add_login_attempt(username)
            return render_template(
                'message.html',
                message='Podane dane logowania są nieprawidłowe.',
                link='/login'
            ) 

@account.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@account.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    
    else:
        username = request.form['username']
        password = request.form['password']
        repeated_password = request.form['password-repeated']
        
        for char in username + password:
            if not char in Config.get_accepted_characters():
                return render_template('message.html', message='Użyto niedozwolonych znaków.', link='/register')

        if len(username) < 1:
            return display_message('Nazwa użytkownika nie może być pusta.', '/register')

        if len(password) < 7:
            return display_message('Minimalna długość hasła wynosi 7 znaków.', '/register')

        if password == repeated_password:
            try:
                security_code = get_random_bytes(32).hex()
                dbm.create_user(username, password, security_code)
                return render_template('security_code.html', security_code=security_code)

            except Exception as e:                              
                return display_message('Podana nazwa użytkownika jest zajęta lub za długa.', '/register')

        else:
            return render_template(
                'message.html',
                message='Hasło i powtórzone hasło muszą być takie same.',
                link='/register'
            )

@account.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if not 'username' in session:
            return redirect('/login')
    
    if request.method == 'GET':
        return render_template('change_password.html')

    else:
        sleep(0.5)
        username = session['username']
        new_password = request.form['new-password']
        new_password_repeated = request.form['repeated-new-password']
        old_password = request.form['old-password']

        for char in username + new_password:
            if not char in Config.get_accepted_characters():
                return render_template('message.html', message='Użyto niedozwolonych znaków.', link='/change-password')

        try:
            dbm.verify_user(username, old_password)

            if new_password == new_password_repeated:
                dbm.change_users_account_password(username, new_password)
            else:
                return render_template(
                    'message.html',
                    message='Hasło i powtórzone hasło muszą być takie same.',
                    link='/change-password'
                )
    
        except Exception as e:
            return render_template('message.html', message='Błąd.', link='/change-password')

        return render_template('message.html', message='Pomyślnie zmieniono hasło', link='/passwords')

@account.route('/restore-account', methods=['GET', 'POST'])
def restore_account():
    if 'username' in session:
            return redirect('/passwords')
    
    if request.method == 'GET':
        return render_template('restore_account.html')
    
    else:
        username = request.form['username']
        security_code = request.form['code'].lower()

        for char in username + security_code:
            if not char in Config.get_accepted_characters():
                return display_message('Użyto niedozwolonych znaków.', '/restore-account')

        try:
            sleep(10)
            dbm.verify_security_code(username, security_code)
            session['username'] = username
            session['restoring_password'] = True
            return redirect('/restore-password')
        
        except:
            return display_message('Podano niepoprawne dane.', '/restore-account')

@account.route('/restore-password', methods=['GET', 'POST'])
def restore_password():
    if not 'restoring_password' in session or not session['restoring_password']:
        return redirect('/change-password')

    if request.method == 'GET':
        return render_template('restore_password.html')
    else:
        username = session['username']
        new_password = request.form['new-password']
        repeated_new_password = request.form['repeated-new-password']

        for char in username + new_password:
            if not char in Config.get_accepted_characters():
                return render_template('message.html', message='Użyto niedozwolonych znaków.', link='/restore-password')

        if new_password == repeated_new_password:
            dbm.change_users_account_password(username, new_password)
            session['restoring_password'] = False
            return redirect('/login')
        else:
            return render_template('message.html', message='różne', link='/restore-password')
