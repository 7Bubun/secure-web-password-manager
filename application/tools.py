from flask import render_template

from db_manager import DataBaseManager
from login_attempts_guard import LoginAttemptsGuard


lag = LoginAttemptsGuard()

try:
    dbm = DataBaseManager()
except:
    print('Nie udało się połączyć z bazą danych.')
    exit(1)

def display_message(message: str, link: str):
    return render_template('message.html', message=message, link=link)
