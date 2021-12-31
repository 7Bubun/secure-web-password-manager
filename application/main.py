from flask import Flask, render_template, request
import db_manager

app = Flask(__name__)
dbm = db_manager.DataBaseManager()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    
    elif request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        try:
            dbm.verify_user(username, password)
            return f'<h1>Hello, {username}!</h1>'
        except Exception as e:
            return render_template('message.html', message=e, link='/login') #TMP message 

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

if __name__ == '__main__':
    app.run(debug=True)
