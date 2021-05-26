"""import sqlite3

con = sqlite3.connect('notthesecretdatabase.db')
curs = con.cursor()


curs.execute('''INSERT INTO not_buffer (target, source, data) VALUES (?, ?, ?);''', ('public', 'public', ''))
con.commit()

curs.execute('''CREATE TABLE not_users (id INTEGER PRIMARY KEY AUTOINCREMENT, name text, email text, secretpassphrase text, friendlist text, friendrequests text, notifications text);''')
con.commit()

curs.execute('''CREATE TABLE not_buffer (user_id INTEGER, target TEXT, source TEXT, data TEXT, FOREIGN KEY(user_id) REFERENCES not_users(id));''')
con.commit()

curs.execute('''CREATE TABLE not_files (owner_id INTEGER, filename TEXT, access TEXT, owner TEXT, data BLOB, FOREIGN KEY(owner_id) REFERENCES not_users(id));''')
con.commit()


curs.execute('''INSERT INTO not_buffer (target, source, data) VALUES (?, ?, ?);''', ('public', 'public', ''))
con.commit()

con.close()"""

from cryptography.fernet import Fernet

def decrypt_message(encrypted_message, key): #  decrypt a message using Fernet module
    f = Fernet(key) #  initialize module in parameter
    decrypted_message = f.decrypt(encrypted_message) # decrypt the message
    return decrypted_message.decode() #  return the decrypted message as plain text

def generate_key():
    key = Fernet.generate_key()
    return key

def encrypt_message(message, key): # a function to encrypt a message
    encoded_message = message.encode() # encode the message (module recievs only bytes)
    f = Fernet(key) #  initiate the module
    encrypted_message = f.encrypt(encoded_message) #  encrypt the message
    return encrypted_message #  return the encrypted message

key = generate_key()
bruh = encrypt_message('bruh', key)
bruh2 = encrypt_message('bruh', key)
print(str(bruh) + ' ' + str(bruh2))
print(bruh==bruh2)