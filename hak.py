"""
from cryptography.fernet import Fernet


def encrypt_message(message, key):
    encoded_message = message.encode()
    f = Fernet(key)
    encrypted_message = f.encrypt(encoded_message)
    return encrypted_message

def generate_key():
    key = Fernet.generate_key()
    return key
def decrypt_message(encrypted_message, key):
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message)
    return decrypted_message.decode()

print(encrypt_message('', generate_key()))"""

import sqlite3

con = sqlite3.connect('notthesecretdatabase.db')
curs = con.cursor()

curs.execute('''CREATE TABLE not_users (id INTEGER PRIMARY KEY AUTOINCREMENT, name text, email text, secretpassphrase text, friendlist text);''')
con.commit()
con.close()
"""
import sqlite3

con = sqlite3.connect('notthesecretdatabase.db', check_same_thread=False)
cur = con.cursor()



email = '2tomshlomi@gmail.com'
cur.execute('''SELECT friendlist FROM not_users WHERE email=(?);''', (str(email),))
con.commit()
old_list = cur.fetchall()[0][0]
print(old_list)"""
