from flask import Blueprint, session, request, redirect, render_template
from Crypto.Random import get_random_bytes, new
from time import sleep

from tools import *
from config import Config

MINIMAL_ENTROPY = 2.5

account = Blueprint('account', __name__, static_folder='static', template_folder='templates')

@account.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        if 'username' in session:
            return redirect('/passwords')
        return render_template('login.html')
    
    else:
        if not 'username' in request.form or not 'password' in request.form:
            return display_message('Niepoprawny formularz.', '/account/login')

        sleep(0.7)
        username = request.form['username']
        password = request.form['password']

        lag.refresh_login_attempts()

        if not lag.verify_login_attempt(username):
            return display_message('Konto tymczasowo zablokowane z powodu zbyt dużej liczby prób logowania.', '/account/login')

        if not check_characters(username + password):
            return display_message('Użyto niedozwolonych znaków.', '/account/login')

        try:
            dbm.verify_user(username, password)
            session['username'] = username            
            return redirect('/passwords')
        except:
            lag.add_login_attempt(username)
            return display_message('Podane dane logowania są nieprawidłowe.', '/account/login') 

@account.route('/logout')
def logout():
    session.clear()
    return redirect('/account/login')

@account.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    
    else:
        username = request.form['username']
        password = request.form['password']
        repeated_password = request.form['password-repeated']
        entropy_of_password = calculate_entropy(password)

        if not check_characters(username + password):
            return display_message('Użyto niedozwolonych znaków.', '/account/register')

        if len(username) < 1:
            return display_message('Nazwa użytkownika nie może być pusta.', '/account/register')

        if len(password) < 7:
            return display_message('Minimalna długość hasła wynosi 7 znaków.', '/account/register')

        if entropy_of_password < MINIMAL_ENTROPY:
            return display_message(f'''Hasło nie jest wystarczająco mocne. Entropia hasła: {entropy_of_password},
                minimalny dopuszczalny próg entropii: {MINIMAL_ENTROPY}.''', '/account/register')

        if password == repeated_password:
            try:
                security_code = get_random_bytes(32).hex()
                dbm.create_user(username, password, security_code)
                return render_template('security_code.html', security_code=security_code)

            except:                              
                return display_message('Podana nazwa użytkownika jest zajęta lub za długa.', '/account/register')

        else:
            return display_message('Hasło i powtórzone hasło muszą być takie same.', '/account/register')

@account.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if not 'username' in session:
            return redirect('/account/login')
    
    if request.method == 'GET':
        return render_template('change_password.html')

    else:
        sleep(0.5)
        username = session['username']
        new_password = request.form['new-password']
        new_password_repeated = request.form['repeated-new-password']
        old_password = request.form['old-password']
        entropy_of_password = calculate_entropy(new_password)

        if len(new_password) < 7:
            return display_message('Minimalna długość hasła wynosi 7 znaków.', '/account/change-password')

        if not check_characters(username + new_password):
            return display_message('Użyto niedozwolonych znaków.', '/account/change-password')

        if entropy_of_password < MINIMAL_ENTROPY:
            return display_message(f'''Hasło nie jest wystarczająco mocne. Entropia hasła: {entropy_of_password},
                minimalny dopuszczalny próg entropii: {MINIMAL_ENTROPY}.''', '/account/change-password')

        try:
            dbm.verify_user(username, old_password)

            if new_password == new_password_repeated:
                dbm.change_users_account_password(username, new_password)
            else:
                return display_message('Hasło i powtórzone hasło muszą być takie same.', '/account/change-password')
    
        except:
            return display_message('Błąd.', link='/account/change-password')

        return display_message('Pomyślnie zmieniono hasło', link='/passwords')

@account.route('/restore-account', methods=['GET', 'POST'])
def restore_account():
    if 'username' in session:
            return redirect('/passwords')
    
    if request.method == 'GET':
        return render_template('restore_account.html')
    
    else:
        username = request.form['username']
        security_code = request.form['code'].lower()

        if not check_characters(username + security_code):
            return display_message('Użyto niedozwolonych znaków.', '/account/restore-account')

        try:
            sleep(10)
            dbm.verify_security_code(username, security_code)
            session['username'] = username
            session['restoring_password'] = True
            return redirect('/account/restore-password')
        
        except:
            return display_message('Podano niepoprawne dane.', '/account/restore-account')

@account.route('/restore-password', methods=['GET', 'POST'])
def restore_password():
    if not 'restoring_password' in session or not session['restoring_password']:
        return redirect('/password-management/change-password')

    if request.method == 'GET':
        return render_template('restore_password.html')
    else:
        username = session['username']
        new_password = request.form['new-password']
        repeated_new_password = request.form['repeated-new-password']
        entropy_of_password = calculate_entropy(new_password)

        if len(new_password) < 7:
            return display_message('Minimalna długość hasła wynosi 7 znaków.', '/account/restore-password')

        if not check_characters(username + new_password):
            return display_message('Użyto niedozwolonych znaków.', '/password-management/restore-password')

        if entropy_of_password < MINIMAL_ENTROPY:
            return display_message(f'''Hasło nie jest wystarczająco mocne. Entropia hasła: {entropy_of_password},
                minimalny dopuszczalny próg entropii: {MINIMAL_ENTROPY}.''', '/account/restore-password')

        if new_password == repeated_new_password:
            dbm.change_users_account_password(username, new_password)
            session['restoring_password'] = False
            return redirect('/account/login')
        else:
            return display_message('Hasło i powtórzone hasło muszą być takie same.', link='/password-management/restore-password')
