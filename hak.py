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

from cv2 import VideoCapture
import cv2

p = VideoCapture(0)
while(True):
      
    # Capture the video frame
    # by frame
    ret, frame = p.read()
  
    # Display the resulting frame
    cv2.imshow('frame', frame)
    print(len(frame))
      
    # the 'q' button is set as the
    # quitting button you may use any
    # desired button of your choice
    if cv2.waitKey(1) & 0xFF == ord('q'):
        break