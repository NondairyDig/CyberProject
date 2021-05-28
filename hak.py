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

from User import User
import socket
import pyaudio

p = pyaudio.PyAudio()

u = User('bruh@gmail.com', 'bruhbruh', socket.socket())
stream = p.open(format=pyaudio.paInt16, channels=1, rate=4000, output=True)
stream_rec = p.open(format=pyaudio.paInt16, channels=1, rate=4000, input=True,
                        frames_per_buffer=1024)

while True:
    u.sound(stream, u.record(stream_rec))