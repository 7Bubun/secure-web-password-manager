from argon2 import PasswordHasher
from Crypto.Protocol.KDF import PBKDF2
from os import environ
import mysql.connector

from config import Config


class DataBaseManager:

    def __init__(self):
        passphrase = 'passphrase' # not secure yet
        salt = b'salt' # not secure yet
        self.key = PBKDF2(passphrase, salt, count=1234).hex()
        
        self.connection = mysql.connector.connect(
            host='localhost',
            user='password_manager',
            password='843gfbwufb239eubswsfhsife', # environ.get('PM_SECRET'),
            database='PASSWORD_MANAGER'
        )

        f = open('pepper', 'rb')
        self.pepper = f.read()
        f.close()

        f = open('initialization_vector', 'rb')
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

    def create_user(self, username: str, password: str):
        password_prepared = bytes(password, 'ascii') + self.pepper
        hashed_password = self.hasher.hash(password_prepared)
        
        # NOT SECURE YET
        query = f'INSERT INTO USERS(USERNAME, HASHED_PASSWORD) VALUES ("{username}", "{hashed_password}")'
        cursor = self.connection.cursor()
        cursor.execute(query)
        self.connection.commit()
        cursor.close()

    def verify_user(self, username: str, password: str):
        # NOT SECURE YET
        query = f'SELECT U.HASHED_PASSWORD FROM USERS AS U WHERE U.USERNAME = "{username}"'
        cursor = self.connection.cursor()
        cursor.execute(query)
        result = cursor.fetchone()[0]
        cursor.close()

        password_prepared = bytes(password, 'ascii') + self.pepper
        return self.hasher.verify(result, password_prepared)

    def get_users_passwords(self, username: str):
        # NOT SECURE YET
        query = f'''SELECT P.NAME_OF_PASSWORD, AES_DECRYPT(P.VALUE_OF_PASSWORD, UNHEX("{self.key}"), "{str(self.init_vector)}"),
                        P.OWNER_OF_PASSWORD, P.ID FROM PASSWORDS AS P WHERE P.OWNER_OF_PASSWORD = "{username}"'''
        cursor = self.connection.cursor()
        cursor.execute(query)
        result = [(data[0], data[1].decode(), data[2], data[3]) for data in cursor]
        cursor.close()
        return result

    def add_password(self, user: str, name_of_password: str, value: str):
        
        # NOT SECURE YET (SQL inj, XSS, no encryption)
        query = f'''INSERT INTO PASSWORDS(NAME_OF_PASSWORD, VALUE_OF_PASSWORD, OWNER_OF_PASSWORD) 
                        VALUES("{name_of_password}", AES_ENCRYPT("{value}", UNHEX("{self.key}"),
                        "{str(self.init_vector)}"), "{user}")
        '''
        cursor = self.connection.cursor()
        cursor.execute(query)
        self.connection.commit()
        cursor.close()

    def update_password(self, id: int, name: str, value: str):
        # NOT SECURE YET
        query = f'''UPDATE PASSWORDS SET NAME_OF_PASSWORD = "{name}",
                        VALUE_OF_PASSWORD = AES_ENCRYPT("{value}", UNHEX("{self.key}"), "{str(self.init_vector)}")
                        WHERE ID = {id}
        '''
        cursor = self.connection.cursor()
        cursor.execute(query)
        self.connection.commit()
        cursor.close()

    def delete_password(self, id: int):
        cursor = self.connection.cursor()
        query = f'DELETE FROM SHARES WHERE ID_OF_PASSWORD = {id}'
        cursor.execute(query)
        query = f'DELETE FROM PASSWORDS WHERE ID = {id}'
        cursor.execute(query)
        self.connection.commit()
        cursor.close()

    def get_users_that_got_password_through_sharing(self, password_id: int):
        query = f'SELECT S.SHARED_TO FROM SHARES AS S WHERE S.ID_OF_PASSWORD = {password_id}'
        cursor = self.connection.cursor()
        cursor.execute(query)
        result = list(cursor)
        cursor.close()
        return result        

    def share_password(self, password_id: int, share_receivers_username: str):
        # NOT SECURE YET
        query = f'INSERT INTO SHARES(ID_OF_PASSWORD, SHARED_TO) VALUES({password_id}, "{share_receivers_username}")'
        cursor = self.connection.cursor()
        cursor.execute(query)
        self.connection.commit()
        cursor.close()

    def get_passwords_shared_to_user(self, username: str):
        query = f'''SELECT P.NAME_OF_PASSWORD, AES_DECRYPT(P.VALUE_OF_PASSWORD, UNHEX("{self.key}"), "{str(self.init_vector)}"),
                        P.OWNER_OF_PASSWORD, P.ID FROM PASSWORDS AS P, SHARES AS S 
                        WHERE P.ID = S.ID_OF_PASSWORD AND S.SHARED_TO = "{username}"
        '''
        cursor = self.connection.cursor()
        cursor.execute(query)
        result = [(data[0], data[1].decode(), data[2], data[3]) for data in cursor]
        cursor.close()
        return result
