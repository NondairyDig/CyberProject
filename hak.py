"""import sqlite3

con = sqlite3.connect('notthesecretdatabase.db')
curs = con.cursor()

curs.execute('''CREATE TABLE not_users (id INTEGER PRIMARY KEY AUTOINCREMENT, name text, email text, secretpassphrase text, friendlist text);''')
con.commit()

curs.execute('''CREATE TABLE not_buffer (user_id INTEGER, target TEXT, source TEXT, data TEXT, FOREIGN KEY(user_id) REFERENCES not_users(id));''')
con.commit()

curs.execute('''CREATE TABLE not_files (owner_id INTEGER, filename TEXT, access TEXT, owner TEXT, data BLOB, FOREIGN KEY(owner_id) REFERENCES not_users(id));''')
con.commit()
con.close()"""

import sqlite3

com = sqlite3.connect('notthesecretdatabase.db')
cur = com.cursor()

cur.execute('''SELECT data FROM not_files WHERE filename = (?);''', ('B&H Invoice.pdf',))
data = cur.fetchall()[0][0]
f = open('bruh.pdf', 'wb')
f.write(data)
