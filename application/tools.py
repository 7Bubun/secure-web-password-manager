from flask import render_template
from math import log2

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

def calculate_entropy(text):
    signs = {}
    entropy = 0

    for char in text:
        if char in signs:
            signs[char] += 1
        else:
            signs[char] = 1

    for s in signs:
        p = signs[s] / len(text)
        entropy -= p * log2(p)

    return entropy
