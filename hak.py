"""import sqlite3

con = sqlite3.connect('notthesecretdatabase.db')
curs = con.cursor()


curs.execute('''CREATE TABLE not_users (id INTEGER PRIMARY KEY AUTOINCREMENT, name text, email text, secretpassphrase text, friendlist text, friendrequests text);''')
con.commit()

curs.execute('''CREATE TABLE not_buffer (target TEXT, source TEXT, data TEXT);''')
con.commit()

curs.execute('''CREATE TABLE not_files (filename TEXT, access TEXT, owner TEXT, data BLOB);''')
con.commit()

curs.execute('''INSERT INTO not_buffer (target, source, data) VALUES (?, ?, ?);''', ('public', 'public', ''))
con.commit()

con.close()"""