from time import sleep
from flask import Flask, redirect, render_template, request, session
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

import db_manager

app = Flask(__name__)   # TO DO: store password in env
app.secret_key = PBKDF2('drowssap', salt=get_random_bytes(8), count=1234)
dbm = db_manager.DataBaseManager()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        if 'username' in session:
            return redirect('/passwords')
        return render_template('login.html')
    
    elif request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        try:
            dbm.verify_user(username, password)
            session['username'] = username            
            return redirect('/passwords')
        except Exception as e:
            return render_template('message.html', message=e, link='/login') #TMP message 

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    
    elif request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        repeated_password = request.form['password-repeated']
        
        if password == repeated_password:
            try:
                # TMP
                security_code = get_random_bytes(32).hex()

                dbm.create_user(username, password, security_code)

                return render_template('security_code.html', security_code=security_code)
            except Exception as e:                              
                return render_template('message.html', message=f'DB error: {e}', link='/') #TMP message

        else:
            return render_template('message.html', message='różne', link='/register') #TMP message

@app.route('/change-password')
def change_password():
    if not 'username' in session:
        return redirect('/login')

    return render_template('change_password.html')

@app.route('/change-password', methods=['POST'])
def change_password_post():
    if not 'username' in session:
        return redirect('/login')

    username = session['username']
    new_password = request.form['new-password']
    new_password_repeated = request.form['repeated-new-password']
    old_password = request.form['old-password']

    try:
        dbm.verify_user(username, old_password)

        if new_password == new_password_repeated:
            dbm.change_users_account_password(username, new_password)
        else:
            return render_template('message.html', message='różne', link='/change-password') # TMP message
    
    except Exception as e:
        return render_template('message.html', message=e, link='/change-password') # TMP message

    return render_template('message.html', message='Pomyślnie zmieniono hasło', link='/passwords')

@app.route('/restore-account')
def restore_account():
    if 'username' in session:
        return redirect('/passwords')

    return render_template('restore_account.html')

@app.route('/restore-account', methods=['POST'])
def restore_account_post():
    if 'username' in session:
        return redirect('/passwords')

    username = request.form['username']
    security_code = request.form['code'].lower()

    try:
        sleep(10)
        dbm.verify_security_code(username, security_code)
        session['username'] = username
        session['restoring_password'] = True
        return redirect('/restore-password')

    except Exception as e:
        return render_template('message.html', message=e, link='/restore-account') # TMP message

@app.route('/restore-password')
def restore_password():
    if not 'restoring_password' in session or not session['restoring_password']:
        return redirect('/change-password')

    return render_template('restore_password.html')

@app.route('/restore-password', methods=['POST'])
def restore_password_post():
    if not 'restoring_password' in session or not session['restoring_password']:
        return redirect('/change-password')

    username = session['username']
    new_password = request.form['new-password']
    repeated_new_password = request.form['repeated-new-password']

    if new_password == repeated_new_password:
        dbm.change_users_account_password(username, new_password)
        session['restoring_password'] = False
        return redirect('/login')
    else:
        return render_template('message.html', message='różne', link='/restore-password')

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

@app.route('/password-management/action', methods=['POST'])
def choose_action():
    if not 'username' in session:
        return redirect('/login')

    password_id = int(request.form['id'])
    password_name = request.form['name']
    password_value = request.form['value']
    password_owner = request.form['owner']
    action = request.form['action']
    
    if action == 'update':
        return render_template(
            'password_update.html',
            id=password_id,
            name=password_name,
            value=password_value,
            owner=password_owner
        )
        
    elif action == 'delete':
        return render_template(
            'password_delete.html',
            id=password_id,
            name=password_name,
            value=password_value,
            owner=password_owner
        )
        
    elif action == 'share':
        return render_template(
            'sharing_panel.html',
            users_and_share_ids=dbm.get_users_that_got_password_through_sharing_and_share_ids(password_id),
            passwords_id=password_id,
            passwords_name=password_name,
            owner=password_owner
        )

    else:
        return redirect('/passwords')

@app.route('/password-management/add', methods=['POST'])
def add_password():
    if not 'username' in session:
        return redirect('/login')

    dbm.add_password(
        session['username'],
        request.form['name'],
        request.form['password']
    )

    return redirect('/passwords')

@app.route('/password-management/update', methods=['POST'])
def update_password(): 
    if not 'username' in session:
        return redirect('/login')
    
    if request.form['owner'] == session['username']:
        dbm.update_password(
            request.form['id'],
            request.form['name'],
            request.form['value']
        )

    return redirect('/passwords')

@app.route('/password-management/delete', methods=['POST'])
def delete_password():
    if not 'username' in session:
        return redirect('/login')

    if request.form['owner'] == session['username']:
        dbm.delete_password(request.form['id'])
    
    return redirect('/passwords') 

@app.route('/shares-management/add', methods=['POST'])
def share():
    if not 'username' in session:
        return redirect('/login')

    if request.form['owner'] == session['username']:
        dbm.share_password(int(request.form['id']), request.form['username'])    

    return redirect('/passwords')

@app.route('/shares-management/delete-as-owner', methods=['POST'])
def unshare_as_owner():
    if not 'username' in session:
        return redirect('/login')

    if request.form['owner'] == session['username']:
        dbm.unshare_password(request.form['share_id'])

    return redirect('/passwords')

@app.route('/shares-management/delete-as-receiver', methods=['POST'])
def unshare_as_receiver():
    if not 'username' in session:
        return redirect('/login')

    id_of_share = request.form['share_id']
    receiver = dbm.get_user_that_password_is_shared_to(id_of_share)
    print(receiver)

    if receiver == session['username']:
        dbm.unshare_password(id_of_share)

    return redirect('/passwords')

if __name__ == '__main__':
    app.run(debug=True)
