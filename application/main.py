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
                dbm.create_user(username, password)
                return render_template('message.html', message='Zarejestrowano pomyślnie', link='/login')
            except Exception as e:                              
                return render_template('message.html', message=f'DB error: {e}', link='/') #TMP message

        else:
            return render_template('message.html', message='różne', link='/register') #TMP message

@app.route('/passwords')
def passwords():
    if 'username' in session:
        passwords = dbm.get_users_passwords(session['username'])
        return render_template('passwords.html', user=session['username'], list_of_passwords=passwords)
    else:
        return redirect('/login')

@app.route('/password-management/add', methods=['POST'])
def add_password():
    if request.method == 'POST':
        dbm.add_password(
            session['username'],
            request.form['name'],
            request.form['password']
        )
        return redirect('/passwords')

@app.route('/password-management/update', methods=['POST'])
def update_password(): 
    dbm.update_password(
        request.form['id'],
        request.form['name'],
        request.form['value']
    )
    return redirect('/passwords')

@app.route('/password-management/action', methods=['POST'])
def update():
    if not 'username' in session:
        return redirect('/login')

    password_id = int(request.form['id'])
    password_name = request.form['name']
    password_value = request.form['value']
    action = request.form['action']
    
    if action == 'update':
        return render_template('password_update.html', id=password_id, name=password_name, value=password_value)
    elif action == 'delete':
        return 'to do'
    elif action == 'share':
        return 'to do'
    else:
        return redirect('/passwords')

if __name__ == '__main__':
    app.run(debug=True)
