import threading
import socket
from tkinter.constants import TRUE
import rsa
import time
from cryptography.fernet import *
from hashlib import sha3_256
import sqlite3

host = '192.168.1.254'
port = 5554
clients = []
public = []
buffer = b''
files = {}
con = sqlite3.connect('notthesecretdatabase.db', check_same_thread=False)
cur = con.cursor()
check = False
voice_cl = []
video_cl = []


def verify(c, addr): #  a function to verify the connection between the server and client (client socket, client address)
    (pubv, privv) = rsa.newkeys(511) #  generate a public and privat key for rsa encryption
    message = 'ö∞øⁿŒç¼•¥Ωü§◙±©'.encode() #  a message to verify
    signature = rsa.sign(message, privv, 'SHA-1') #  create a signature of server
    c.send(str(pubv.n).encode()) #  send public key part
    c.send(str(pubv.e).encode()) #  send public key part
    c.send(signature) # send signature to compare
    message = '©±°◙§≡üΩ¥•¼·ëçŒ▓ⁿø∞ö'.encode() #  shared secret to verify
    no = int(c.recv(154).decode()) #  get the public key part
    eo = int(c.recv(5).decode()) #  get the public key part
    pubv = rsa.key.PublicKey(no, eo) #  assemble the public key
    signature = c.recv(64) #  get the signature 
    time.sleep(0.3)
    rsa.verify(message, signature, pubv) #  verify the signature
    print('Client: ' + str(addr) + ' Verification Completed')


def logincheck(c): #  a function of checking the login (client socket)
    (pub, priv) = rsa.newkeys(511) #  generate a public and privat key for rsa encryption
    c.send(str(pub.n).encode()) #  send public key part
    c.send(str(pub.e).encode()) #  send public key part
    u = c.recv(64) #  get encrypted email
    time.sleep(0.1) #  wait
    p = c.recv(64)  #  get encrypted password hash
    m1 = rsa.decrypt(u, priv).decode() #  decrypt email
    m2 = rsa.decrypt(p, priv) #  decrypt password hash
    p = sha3_256() #  initialize hashing module
    p.update(m2 + m1.encode()) #  insert password hash and salt
    pf = p.digest() #  hash
    cur.execute('''SELECT email, friendlist, name FROM not_users WHERE email = (?) AND secretpassphrase = (?);''', (str(m1), str(pf))) #  check for matching email and password hash
    con.commit() #  commit database command
    res = cur.fetchall() # get results from dtabase command
    if res == []: #  if no match found
        return False, False, False, False #  return False 
    if res[0][0] == str(m1): #  if email matches database records
        for cl in clients:
            if cl[1] == res[0][2]:
                return False, 'imp', False, False
        friend_list = res[0][1] #  if password matches database records
        return res[0][2], pf, True, friend_list # return username, password, Authurization status, friend list
    return False, False, False, False #  return False 


def login(c, sesk): #  a function to initialize the login process
    ayy = logincheck(c) # call the logincheck function
    time.sleep(0.5)
    keke = ayy[1] #  the password returned
    nname = ayy[0] #  the username returned
    auth = ayy[2]  #  if authorized returned
    f_list = ayy[3] #  friendlist returned
    n = int(c.recv(154).decode()) #  get the public key part 
    e = int(c.recv(5).decode()) #  get the public key part
    publ = rsa.key.PublicKey(n, e) #  assemble the public key
    if keke == 'imp':
        log = rsa.encrypt((b'impost'), publ) #  send that log-in was not authorized
        c.send(log) # send
        return False, 'no' #  return login was not authorized with bool and string
    if auth: #  if the server authorized access
        log = rsa.encrypt((keke + b'auth'), publ) #  send password + salt to confirm login
        c.send(log) #  send
        time.sleep(0.2) #  wait
        secret_key = rsa.encrypt(sesk, publ) #  send session key to client
        c.send(secret_key) #  send
        time.sleep(0.2) # wait
        nicknam = rsa.encrypt(nname.encode(), publ) #  send nickname from database
        c.send(nicknam) # send
        return True, nname, f_list # return authorization confirmation, nickname, friendlist
    else: #  if log-in not authorized
        log = rsa.encrypt((b'login failed'), publ) #  send that log-in was not authorized
        c.send(log) # send
        return False, 'no' #  return login was not authorized with bool and string


def signup(c):
    (pub, priv) = rsa.newkeys(511)
    c.send(str(pub.n).encode())
    c.send(str(pub.e).encode())
    u = c.recv(64)
    p = c.recv(64)
    n = c.recv(64)
    m1 = rsa.decrypt(u, priv)
    m2 = rsa.decrypt(p, priv)
    m3 = rsa.decrypt(n, priv).decode()
    time.sleep(0.5)
    nk = int(c.recv(154).decode())
    e = int(c.recv(5).decode())
    pub = rsa.key.PublicKey(nk, e)
    cur.execute('''SELECT email FROM not_users WHERE email = (?);''', (str(m1.decode()),))
    con.commit()
    em = cur.fetchall()
    cur.execute('''SELECT name FROM not_users WHERE name = (?);''', (str(m3),))
    con.commit()
    username = cur.fetchall()
    if em != [] or username != []:
        c.send(rsa.encrypt('fialad'.encode(), pub))
        return False
    p = sha3_256()
    p.update(m2 + m1)
    cur.execute('''INSERT INTO not_users (name, email, secretpassphrase, friendlist, friendrequests, notifications)
                VALUES (?, ?, ?, ?, ?, ?);''', (str(m3), str(m1.decode()), str(p.digest()), '', '', ''))
    con.commit()
    c.send(rsa.encrypt('succep'.encode(), pub))
    return True


def get_friends(email):
    cur.execute('''SELECT friendlist FROM not_users WHERE email=(?);''', (str(email),))
    con.commit()
    flist = cur.fetchall()
    if flist == []:
        return ''
    return flist[0][0]


def add_friend(name, friend):
    cur.execute('''SELECT name FROM not_users WHERE name = (?);''', (str(friend),))
    con.commit()
    ans = cur.fetchall()
    if ans == []:
        return False
    cur.execute('''SELECT friendrequests FROM not_users WHERE name = (?);''', (str(friend),))
    con.commit()
    current = cur.fetchall()
    time.sleep(0.000001)
    if current == []:
        updated = (str(name) + '-')
    else:
        updated = (str(current[0][0]) + str(name) + '-')
    cur.execute('''UPDATE not_users SET friendrequests = (?) WHERE name = (?);''', (updated, str(friend)))
    con.commit()
    return True


def remove_friend(email, friend):
    old_list = get_friends(email)
    if old_list == []:
        return
    new_list = old_list.replace(str(friend) + '-', '')
    cur.execute('''UPDATE not_users SET friendlist = (?) WHERE email=(?);''', (new_list, email))
    con.commit()
    
    cur.execute('''SELECT friendlist FROM not_users WHERE name=(?);''', (friend,))
    con.commit()
    old_list = cur.fetchall()[0][0]
    if old_list == []:
        return
    cur.execute('''SELECT name FROM not_users WHERE email = (?);''', (email,))
    con.commit()
    nickname = cur.fetchall()[0][0]
    new_list = old_list.replace(nickname + '-', '')
    cur.execute('''UPDATE not_users SET friendlist = (?) WHERE name=(?);''', (new_list, friend))
    con.commit()
    cur.execute('''DELETE FROM not_buffer WHERE target = (?) AND source=(?);''', (nickname, friend))
    con.commit()
    cur.execute('''DELETE FROM not_buffer WHERE target = (?) AND source=(?);''', (friend, nickname))
    con.commit()


def generate_key():
    key = Fernet.generate_key()
    return key


def encrypt_message(message, key):
    encoded_message = message.encode()
    f = Fernet(key)
    encrypted_message = f.encrypt(encoded_message)
    return encrypted_message


def encrypt_file(file, key):
    f = Fernet(key)
    encrypted_file = f.encrypt(file)
    return encrypted_file


def decrypt_message(encrypted_message, key):
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message)
    return decrypted_message.decode()


def decrypt_file(encrypted_file, key):
    f = Fernet(key)
    decrypted_file = f.decrypt(encrypted_file)
    return decrypted_file


def broadcast(message, target, current_name, conv, current=''):
    if target == 'public':
        cur.execute('''UPDATE not_buffer SET data = data || (?) WHERE target = (?);''', (message + '\r\n', 'public'))
        con.commit()
        for cl in public:
            if cl[0] is current:
                key = cl[2]
                query = encrypt_message(message, key)
                cl[0].send(encrypt_message(str(len(query)), key))
                cl[0].send(query)
    else:
        cur.execute('''SELECT data FROM not_buffer WHERE target = (?) AND source = (?);''', (target, current_name))
        con.commit()
        old_data = cur.fetchall()
        if old_data == []:
            new_data = message + '\r\n'
        else:
            new_data = old_data[0][0] + message + '\r\n'
        cur.execute('''UPDATE not_buffer SET data = (?) WHERE target = (?) AND source = (?);''', (new_data, target, current_name))
        con.commit()
        cur.execute('''UPDATE not_buffer SET data = (?) WHERE target = (?) AND source = (?);''', (new_data, current_name, target))
        con.commit()
        if conv != current_name:
            return
        else:
            for cl in clients:
                if cl[0] is not current and cl[1] == target:
                    key = cl[2]
                    query = encrypt_message(message, key)
                    cl[0].send(encrypt_message(str(len(query)), key))
                    cl[0].send(query)


def handle(client, addr, session_key):
    global check
    m = client.recv(1).decode()
    if m == 'V':
        pass
    else:
        client.close()
        return
    try:
        verify(client, addr)
    except:
        print('could not verify')
        return
    time.sleep(1)
    m = client.recv(1).decode()
    if m == 'S':
        if signup(client):
            m = client.recv(1).decode()
            if m == 'L':
                v = login(client, session_key)
            if v[0]:
                pass
            else:
                return
        else:
            return
    elif m == 'L':
        v = login(client, session_key)
        if v[0]:
            pass
        else:
            return
    client.recv(1024)
    clients.append([client, v[1], session_key, ''])
    time.sleep(0.3)
    while True:
        check = False
        try:
            buff = decrypt_message(client.recv(100), session_key)
            message = decrypt_message(client.recv(int(buff)), session_key)
            print(message)
            split = message.split('<>')
            if message == split: #  prevent not compatable packet sending
                print(str(addr) + ' disconnected')
                for cl in clients:
                    if cl[0] == client:
                        clients.remove(cl)
                        break
                try:
                    public.remove((client, v[1], session_key))
                except:
                    pass
                client.close()
                return
            if split[0] == 'üΩ¥':
                ans = add_friend(split[1], split[2])
                if ans:
                    query = encrypt_message('added', session_key)
                    client.send(encrypt_message(str(len(query)), session_key))
                    client.send(query)
                else:
                    query = encrypt_message('failed', session_key)
                    client.send(encrypt_message(str(len(query)), session_key))
                    client.send(query)

            elif split[0] == '§≡üΩ¥•¼': #  client-server signal for getting message history
                if split[1] == 'public':
                    cur.execute('''SELECT data FROM not_buffer WHERE target = (?) AND source = (?);''', ('public', 'public'))
                    con.commit()
                else:
                    cur.execute('''SELECT data FROM not_buffer WHERE target = (?) AND source = (?);''', (split[1], split[2]))
                    con.commit()
                history = cur.fetchall()
                if history == []:
                    query = encrypt_message('', session_key)
                    client.send(encrypt_message(str(len(query)), session_key))
                    client.send(query)
                else:
                    query = encrypt_message(str(history[0][0]), session_key)
                    client.send(encrypt_message(str(len(query)), session_key))
                    client.send(query)

            elif split[0] == 'é': #  client-server signal for getting number of friend requests
                cur.execute('''SELECT friendrequests FROM not_users WHERE name =(?);''', (split[1],))
                con.commit()
                requests = cur.fetchall()[0][0].split('-')
                query = encrypt_message(str(len(requests) - 1), session_key)
                client.send(encrypt_message(str(len(query)), session_key))
                client.send(query)

            elif split[0] == '₧—é': #  client-server signal for getting friend requests
                cur.execute('''SELECT friendrequests FROM not_users WHERE name =(?);''', (split[1],))
                con.commit()
                requests = cur.fetchall()[0][0]
                query = encrypt_message(requests, session_key)
                client.send(encrypt_message(str(len(query)), session_key))
                client.send(query)

            elif split[0] == 'Ω¥•¼': # client-server signal for updating communication target
                for cl in clients:
                    if cl[1] == v[1]:
                        cl[3] = split[1]

            elif split[0] == 'éè╣': #  client-sserver signal for handling friend requests
                if split[1] == 'accept':
                    cur.execute('''SELECT friendrequests FROM not_users WHERE name =(?);''', (split[2],))
                    con.commit()
                    requests = cur.fetchall()[0][0]
                    new = requests.replace(f'{split[3]}-', '')
                    cur.execute('''UPDATE not_users SET friendrequests = (?) WHERE name = (?);''', (new, split[2]))
                    con.commit()
                    cur.execute('''SELECT friendlist FROM not_users WHERE name =(?);''', (split[3],))
                    con.commit()
                    friends = cur.fetchall()
                    if friends == []:
                        new_f = split[2] + '-'
                    else:
                        new_f = friends[0][0] + split[2] + '-'
                    cur.execute('''UPDATE not_users SET friendlist = (?) WHERE name = (?);''', (new_f, split[3]))
                    con.commit()
                    cur.execute('''SELECT friendlist FROM not_users WHERE name =(?);''', (split[2],))
                    con.commit()
                    friends = cur.fetchall()
                    if friends == []:
                        new_f = split[3] + '-'
                    else:
                        new_f = friends[0][0] + split[3] + '-'
                    cur.execute('''UPDATE not_users SET friendlist = (?) WHERE name = (?);''', (new_f, split[2]))
                    con.commit()
                    cur.execute('''INSERT INTO not_buffer (target, source, data) VALUES (?, ?, ?);''', (split[3], split[2], ''))
                    con.commit()
                    cur.execute('''INSERT INTO not_buffer (target, source, data) VALUES (?, ?, ?);''', (split[2], split[3], ''))
                    con.commit()

                elif split[1] == 'reject':
                    cur.execute('''SELECT friendrequests FROM not_users WHERE name =(?);''', (split[2],))
                    con.commit()
                    requests = cur.fetchall()[0][0]
                    new = requests.replace(f'{split[3]}-', '')
                    cur.execute('''UPDATE not_uesrs SET friendrequests = (?);''', (new,))
                    con.commit()

            elif split[0] == '™╣¶': #  client-server signal for removing a friend
                remove_friend(split[1], split[2])
                query = encrypt_message('removed', session_key)
                client.send(encrypt_message(str(len(query)), session_key))
                client.send(query)

            elif split[0] == 'ø∞ö': #  client-server signal for getting friendlist
                friendlist = get_friends(split[1])
                if friendlist == []:
                    pass
                else:
                    status = friendlist.split('-')
                    friendlist = ''
                    for f in status:
                        for cl in clients:
                            if f == cl[1]:
                                friendlist += f + '(online)-'
                            else:
                                friendlist += f + '(offline)-'
                query = encrypt_message(friendlist, session_key)
                client.send(encrypt_message(str(len(query)), session_key))
                client.send(query)

            elif split[0] == 'ƒ₧—©±°◙': #  client-server signal for uploading a file to the server
                cur.execute('''SELECT id, name FROM not_users WHERE name = (?) ;''', (v[1],))
                con.commit()
                ans = cur.fetchall()[0]
                cur.execute('''INSERT INTO not_files (owner_id, filename, access, owner) VALUES (?, ?, ?, ?);''' , (ans[0], split[1], split[2], ans[1]))
                con.commit()
                data = b''
                while True:
                    buff = decrypt_message(client.recv(100), session_key)
                    if buff == '-1':
                        break
                    data += decrypt_file(client.recv(int(buff)), session_key)
                cur.execute('''UPDATE not_files SET data = (?) WHERE filename = (?);''', (data, split[1]))
                con.commit()
                query = encrypt_message('uploaded successfully©◙ƒ<>', session_key)
                client.send(encrypt_message(str(len(query)), session_key))
                client.send(query)
            
            elif split[0] == '₧ƒ': #  client-server signal for loading files
                cur.execute('''SELECT filename FROM not_files WHERE access = (?) AND owner = (?);''', (split[1], split[2]))
                con.commit()
                filelist = cur.fetchall()
                if filelist == []:
                    query = encrypt_message('', session_key)
                    client.send(encrypt_message(str(len(query)), session_key))
                    client.send(query)
                else:
                    tosend = ''
                    for file in filelist:
                        tosend += str(file[0]) + '-'
                    query = encrypt_message(tosend, session_key)
                    client.send(encrypt_message(str(len(query)), session_key))
                    client.send(query)

            elif split[0] == '◙°±©—₧ƒ': #  client-server signal for getting a file
                temp = open('files\\temp' + split[1]+split[2], 'rb+')
                cur.execute('''SELECT data FROM not_files WHERE filename = (?) AND access = (?);''', (str(split[1]), str(split[2])))
                con.commit()
                data = cur.fetchall()[0][0]
                print(data)
                temp.write(data)
                while True:
                    data = temp.read(1024)
                    if data == b'':
                        temp.close()
                        client.send(encrypt_message('-1', session_key))
                        break
                    query = encrypt_file(data, session_key)
                    client.send(encrypt_message(str(len(query)), session_key))
                    client.send(query)
                    time.sleep(0.0000000001)

            elif split[0] == '▓quitf': # signal for quiting temporerly
                query = encrypt_message('filing±°<>', session_key)
                client.send(encrypt_message(str(len(query)), session_key))
                client.send(query)

            elif split[0] == '▓quit': #  signal for quiting
                query = encrypt_message('byebye±°<>', session_key) #  send encrypted signal for quitting
                client.send(encrypt_message(str(len(query)), session_key))
                client.send(query)

            elif split[0] == 't◙': # server signal for adding or removing from public room
                if split[1] == 'public':
                    public.append((client, v[1], session_key))
                if split[1] == 'quit_pub':
                    public.remove((client, v[1], session_key))

            else: #  if no signal was called then broadcast the message to the target
                for cl in clients:
                    if cl[1] == split[1]:
                        broadcast(split[2], split[1], v[1], cl[3], client)
                        check = True
                        break
                if not check:
                    broadcast(split[2], split[1], v[1], '', client)

        except Exception as e:
            print(e)
            print(str(addr) + ' disconnected')
            for cl in clients:
                if cl[0] == client:
                    clients.remove(cl)
            try:
                public.remove((client, v[1], session_key))
            except:
                pass
            client.close()
            break


def recv_send(c, tar):
    while True:
            try:
                data = c.recv(2828)
            except Exception as e:
                print(e)
                c.close()
                tar.close()
                return
            try:
                tar.send(data)
            except Exception as e:
                print(e)
                c.close()
                tar.close()
                for vo in voice_cl:
                    if vo[0] == c:
                        voice_cl.remove(vo)
                    if vo[0] == tar:
                        voice_cl.remove(vo)
                return

def voice(c):
    global voice_cl
    vkey = b'JlIw6uoJknefy2pI7nzTyb8fnzdewdtqpVrk7AYYxWE='
    buff = decrypt_message(c.recv(100), vkey)
    message = decrypt_message(c.recv(int(buff)), vkey)
    spl = message.split('<>')
    voice_cl.append([c, spl[2], spl[1]])
    ayo = False
    while not ayo:
        try:
            for vo in voice_cl:
                if vo[2] == spl[2] and vo[1] == spl[1]:
                    tar = vo[0]
                    c.send('start'.encode())
                    main_vo_t = threading.Thread(target=recv_send, args=(c, tar))
                    main_vo_t.start()
                    ayo = True
        except:
            c.close()
            return
        time.sleep(0.1)


def voice_channel():
    special = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    special.bind((host, 61441))
    special.listen(9)
    while True:
        c, addr = special.accept()

        thread = threading.Thread(target=voice, args=(c,))
        thread.start()

def recv_send_vid(cli, targ, vkey, tarkey):
    while True:
            try:
                buff = decrypt_message(cli.recv(100), vkey)
                message = decrypt_file(cli.recv(int(buff)), vkey)
            except:
                cli.close()
                targ.close()
                return
            try:
                to_send = encrypt_file(message, tarkey)
                targ.send(encrypt_message(str(len(to_send)), tarkey))
                targ.send(to_send)
            except:
                targ.close()
                cli.close()
                return

def video(cli):
    global video_cl
    vkey = ''
    tarkey = ''
    temp_key = b'JlIw6uoJknefy2pI7nzTyb8fnzdewdtqpVrk7AYYxWE='
    buff = decrypt_message(cli.recv(100), temp_key)
    u_nick = decrypt_message(cli.recv(int(buff)), temp_key)
    for clie in clients:
        if clie[1] == u_nick:
            vkey = clie[2]
    if vkey == '':
        print('b')
        return
    buff = decrypt_message(cli.recv(100), vkey)
    message = decrypt_message(cli.recv(int(buff)), vkey)
    spl = message.split('<>')
    for clie in clients:
        if spl[1] == clie[1]:
            tarkey = clie[2]
    if tarkey == '':
        print('a')
        return
    video_cl.append([cli, spl[2], spl[1], spl[3]])
    if spl[3] == 'recv':
        return
    ayo = False
    while not ayo:
        try:
            for vo in video_cl:
                if vo[2] == spl[2] and vo[1] == spl[1] and vo[3] == 'recv':
                    targ = vo[0]
                    cli.send('start'.encode())
                    main_vid_t = threading.Thread(target=recv_send_vid, args=(cli, targ, vkey, tarkey))
                    main_vid_t.start()
                    ayo = True
        except:
            cli.close()
            return
        time.sleep(0.1)

def video_channel():
    special_vid = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    special_vid.bind((host, 14655))
    special_vid.listen(9)
    while True:
        c, addr = special_vid.accept()

        thread = threading.Thread(target=video, args=(c,))
        thread.start()

def receive():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, 5554))
    s.listen(9)
    v_t = threading.Thread(target=voice_channel)
    v_t.start()
    vid_t = threading.Thread(target=video_channel)
    vid_t.start()
    while True:
        c, addr = s.accept()
        print(f'[{time.strftime("%Y-%m-%d %H:%M:%S",time.localtime())}] connected with {str(addr)}')

        session_key = generate_key()

        thread = threading.Thread(target=handle, args=(c, addr, session_key))
        thread.start()


receive()