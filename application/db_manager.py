from argon2 import PasswordHasher
from Crypto.Protocol.KDF import PBKDF2
from markupsafe import escape
from os import getenv
import mysql.connector

from config import Config


class DataBaseManager:

    def __init__(self):
        passphrase = getenv('PM_PASSPHRASE')
        salt = bytes(getenv('PM_SALT'), 'ascii')
        self.key = PBKDF2(passphrase, salt, count=1234).hex()
        
        self.connection = mysql.connector.connect(
            host='localhost',
            user='password_manager',
            password=getenv('PM_DB'),
            database='PASSWORD_MANAGER'
        )

        f = open(getenv('PATH_TO_PEPPER'), 'rb')
        self.pepper = f.read()
        f.close()

        f = open(getenv('PATH_TO_IV'), 'rb')
        self.init_vector = f.read()
        f.close()

        options = Config.get_hashing_parameters()
        self.hasher = PasswordHasher(
            time_cost=options['time_const'],
            hash_len=options['hash_len'],
            salt_len=options['salt_len']            
        )

        cursor = self.connection.cursor()
        cursor.execute('SET block_encryption_mode = "aes-128-cbc"')
        cursor.close()

    def create_user(self, username: str, password: str, security_code: str):
        username = str(escape(username))
        password = str(escape(password))

        hashed_password = self.hasher.hash(bytes(password, 'ascii') + self.pepper)
        hashed_security_code = self.hasher.hash(self.pepper + bytes.fromhex(security_code))
        
        query = 'INSERT INTO USERS(USERNAME, HASHED_PASSWORD, HASHED_SECURITY_CODE) VALUES (%s, %s, %s)'
        values = (username, hashed_password, hashed_security_code)
        cursor = self.connection.cursor()
        cursor.execute(query, values)
        self.connection.commit()
        cursor.close()

    def verify_user(self, username: str, password: str):
        username = str(escape(username))
        password = str(escape(password))
        
        query = 'SELECT U.HASHED_PASSWORD FROM USERS AS U WHERE U.USERNAME = %s'
        values = (username,)
        cursor = self.connection.cursor()
        cursor.execute(query, values)
        result = cursor.fetchone()[0]
        cursor.close()

        password_prepared = bytes(password, 'ascii') + self.pepper
        return self.hasher.verify(result, password_prepared)

    def change_users_account_password(self, username: str, new_password: str):
        username = str(escape(username))
        new_password = str(escape(new_password))
        
        password_prepared = bytes(new_password, 'ascii') + self.pepper
        hashed_password = self.hasher.hash(password_prepared)
        
        query = 'UPDATE USERS SET HASHED_PASSWORD = %s WHERE USERNAME = %s'
        values = (hashed_password, username)
        cursor = self.connection.cursor()
        cursor.execute(query, values)
        self.connection.commit()
        cursor.close()

    def verify_security_code(self, username: str, security_code: str):
        username = str(escape(username))
        security_code = str(escape(security_code))
        
        query = 'SELECT U.HASHED_SECURITY_CODE FROM USERS AS U WHERE U.USERNAME = %s'
        values = (username,)
        cursor = self.connection.cursor()
        cursor.execute(query, values)
        result = cursor.fetchone()[0]
        cursor.close()
        self.hasher.verify(result, self.pepper + bytes.fromhex(security_code))

    def get_users_passwords(self, username: str):
        username = str(escape(username))
        
        query = '''SELECT P.NAME_OF_PASSWORD, AES_DECRYPT(P.VALUE_OF_PASSWORD, UNHEX(%s), %s),
                        P.OWNER_OF_PASSWORD, P.ID FROM PASSWORDS AS P WHERE P.OWNER_OF_PASSWORD = %s'''
        values = (self.key, str(self.init_vector), username)
        cursor = self.connection.cursor()
        cursor.execute(query, values)
        result = [(data[0], data[1].decode(), data[2], data[3]) for data in cursor.fetchall()]
        cursor.close()
        return result

    def add_password(self, user: str, name_of_password: str, value: str):
        user = str(escape(user))
        name_of_password = str(escape(name_of_password))
        value = str(escape(value))

        query = '''INSERT INTO PASSWORDS(NAME_OF_PASSWORD, VALUE_OF_PASSWORD, OWNER_OF_PASSWORD) 
                        VALUES(%s, AES_ENCRYPT(%s, UNHEX(%s), %s), %s)'''
        values = (name_of_password, value, self.key, str(self.init_vector), user)
        cursor = self.connection.cursor()
        cursor.execute(query, values)
        self.connection.commit()
        cursor.close()

    def update_password(self, password_id: int, name: str, value: str):
        name = str(escape(name))
        value = str(escape(value))

        query = '''UPDATE PASSWORDS SET NAME_OF_PASSWORD = %s, VALUE_OF_PASSWORD = AES_ENCRYPT(%s, UNHEX(%s), %s)
                    WHERE ID = %s'''
        values = (name, value, self.key, str(self.init_vector), password_id)
        cursor = self.connection.cursor()
        cursor.execute(query, values)
        self.connection.commit()
        cursor.close()

    def delete_password(self, password_id: int):
        cursor = self.connection.cursor()
        values = (password_id,)
        
        query = 'DELETE FROM SHARES WHERE ID_OF_PASSWORD = %s'
        cursor.execute(query, values)
        
        query = 'DELETE FROM PASSWORDS WHERE ID = %s'
        cursor.execute(query, values)
        
        self.connection.commit()
        cursor.close()

    def get_users_that_got_password_through_sharing_and_share_ids(self, password_id: int):
        query = 'SELECT S.SHARED_TO, S.ID FROM SHARES AS S WHERE S.ID_OF_PASSWORD = %s'
        values = (password_id,)
        cursor = self.connection.cursor()
        cursor.execute(query, values)
        result = list(cursor)
        cursor.close()
        return result

    def share_password(self, password_id: int, share_receivers_username: str):
        share_receivers_username = str(escape(share_receivers_username))

        query = 'INSERT INTO SHARES(ID_OF_PASSWORD, SHARED_TO) VALUES(%s, %s)'
        values = (password_id, share_receivers_username)
        cursor = self.connection.cursor()
        cursor.execute(query, values)
        self.connection.commit()
        cursor.close()

    def get_passwords_shared_to_user(self, username: str):
        username = str(escape(username))

        query = '''SELECT P.NAME_OF_PASSWORD, AES_DECRYPT(P.VALUE_OF_PASSWORD, UNHEX(%s), %s), P.OWNER_OF_PASSWORD, S.ID
                        FROM PASSWORDS AS P, SHARES AS S WHERE P.ID = S.ID_OF_PASSWORD AND S.SHARED_TO = %s'''
        values = (self.key, str(self.init_vector), username)
        cursor = self.connection.cursor()
        cursor.execute(query, values)
        result = [(data[0], data[1].decode(), data[2], data[3]) for data in cursor]
        cursor.close()
        return result

    def get_user_that_password_is_shared_to(self, id_of_share: int): 
        query = 'SELECT S.SHARED_TO FROM SHARES AS S WHERE S.ID = %s'
        values = (id_of_share,)
        cursor = self.connection.cursor()
        cursor.execute(query, values)
        result = cursor.fetchone()
        cursor.close()
        return result[0]

    def unshare_password(self, id_of_share: int):
        query = 'DELETE FROM SHARES WHERE ID = %s'
        values = (id_of_share,)
        cursor = self.connection.cursor()
        cursor.execute(query, values)
        self.connection.commit()
        cursor.close()
