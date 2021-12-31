from argon2 import PasswordHasher
from os import environ
import mysql.connector

from config import Config


class DataBaseManager:

    def __init__(self):
        self.connection = mysql.connector.connect(
            host='localhost',
            user='password_manager',
            password='843gfbwufb239eubswsfhsife', # environ.get('PM_SECRET'),
            database='PASSWORD_MANAGER'
        )

        self.cursor = self.connection.cursor()
        f = open('pepper', 'rb')
        self.pepper = f.read()
        f.close()

        options = Config.get_hashing_parameters()
        self.hasher = PasswordHasher(
            time_cost=options['time_const'],
            hash_len=options['hash_len'],
            salt_len=options['salt_len']            
        )


    def create_user(self, username, password):
        password_prepared = bytes(password, 'ascii') + self.pepper
        hashed_password = self.hasher.hash(password_prepared)
        
        # NOT SECURE YET
        query = f'INSERT INTO USERS(USERNAME, HASHED_PASSWORD) VALUES ("{username}", "{hashed_password}")'
        self.cursor.execute(query)
        self.connection.commit()

    def verify_user(self, username, password):
        # NOT SECURE YET
        query = f'SELECT U.HASHED_PASSWORD FROM USERS AS U WHERE U.USERNAME = "{username}"'
        self.cursor.execute(query)
        result = self.cursor.fetchone()[0]

        password_prepared = bytes(password, 'ascii') + self.pepper
        return self.hasher.verify(result, password_prepared)
