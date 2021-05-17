import threading
import socket
import rsa
import time
from cryptography.fernet import *
from hashlib import sha3_256
import sqlite3


host = '127.0.0.1'
port = 5554
clients = []
public = []
buffer = b''
files = {}
con = sqlite3.connect('notthesecretdatabase.db', check_same_thread=False)
cur = con.cursor()
buffer_con = sqlite3.connect('buffer.db', check_same_thread=False)
buff_cur = buffer_con.cursor()


def verify(c, addr):
    (pubv, privv) = rsa.newkeys(511)
    message = c.recv(20)
    signature = rsa.sign(message, privv, 'SHA-1')
    c.send(str(pubv.n).encode())
    c.send(str(pubv.e).encode())
    c.send(signature)
    message = '©±°◙§≡üΩ¥•¼·ëçŒ▓✠ⁿø∞ö'.encode()
    c.send(message)
    no = int(c.recv(154).decode())
    eo = int(c.recv(5).decode())
    pubv = rsa.key.PublicKey(no, eo)
    signature = c.recv(64)
    time.sleep(0.3)
    rsa.verify(message, signature, pubv)
    print('Client: ' + str(addr) + ' Verification Completed')


def logincheck(c):
    (pub, priv) = rsa.newkeys(511)
    c.send(str(pub.n).encode())
    c.send(str(pub.e).encode())
    u = c.recv(64)
    time.sleep(0.1)
    p = c.recv(64)
    m1 = rsa.decrypt(u, priv).decode()
    m2 = rsa.decrypt(p, priv)
    p = sha3_256()
    p.update(m2 + m1.encode())
    pf = p.digest()
    cur.execute('''SELECT email, friendlist, name FROM not_users WHERE email = (?) AND secretpassphrase = (?);''', (str(m1), str(pf)))
    con.commit()
    res = cur.fetchall()
    if res == []:
        return False, False, False, False
    if res[0][0] == str(m1):
        friend_list = res[0][1]
        return res[0][2], pf, True, friend_list
    return False, False, False, False


def login(c, sesk):
    ayy = logincheck(c)
    time.sleep(0.5)
    keke = ayy[1]
    nname = ayy[0]
    auth = ayy[2]
    f_list = ayy[3]
    n = int(c.recv(154).decode())
    e = int(c.recv(5).decode())
    publ = rsa.key.PublicKey(n, e)
    if auth:
        log = rsa.encrypt((keke + b'auth'), publ)
        c.send(log)
        time.sleep(0.3)
        secret_key = rsa.encrypt(sesk, publ)
        c.send(secret_key)
        time.sleep(0.2)
        nicknam = rsa.encrypt(nname.encode(), publ)
        c.send(nicknam)
        return True, nname, f_list
    else:
        log = rsa.encrypt((b'login failed'), publ)
        c.send(log)
        return False, 'no'


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
    if cur.fetchall() != []:
        c.send(rsa.encrypt('fialad'.encode(), pub))
        return False
    p = sha3_256()
    p.update(m2 + m1)
    cur.execute('''INSERT INTO not_users
                VALUES (?, ?, ?, ?);''', (str(m3), str(m1.decode()), str(p.digest()), ''))
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


def add_friend(email, friend):
    cur.execute('''SELECT name FROM not_users WHERE name=(?);''', (friend))
    con.commit()
    if cur.fetchall() == []:
        return False
    current = get_friends(email)
    updated = (str(current) + str(friend) + '-')
    cur.execute('''UPDATE not_users SET friendlist=(?) WHERE email=(?);''', (updated, str(email)))
    con.commit()
    return True


def remove_friend(email, friend):
    cur.execute('''SELECT friendlist FROM not_users WHERE email=(?);''', (str(email),))
    con.commit()
    old_list = cur.fetchall()
    if old_list == []:
        return
    new_list = old_list[0].replace(str(friend) + '-', '')
    cur.execute('''UPDATE not_users SET friendlist = (?) WHERE email=(?)''', (new_list, email))
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


def broadcast(message, target, current=''):
    if target == 'public':
        for cl in public:
            if cl[0] is not current:
                key = cl[2]
                cl[0].send(encrypt_message(message, key))
    else:
        for cl in clients:
            if cl[0] is not current and cl[1] == target:
                key = cl[2]
                cl[0].send(encrypt_message(message, key))


def handle(client, addr, session_key):
    client.recv(1024)
    try:
        verify(client, addr)
    except:
        print('could not verify')
        return
    time.sleep(1)
    m = client.recv(1024).decode()
    if len(m) == 1:
        if m == 'S':
            if signup(client):
                m = client.recv(1024).decode()
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
    client.send(encrypt_message(str(v[2]), session_key))
    client.recv(1024)
    clients.append((client, v[1], session_key))
    time.sleep(0.3)
    while True:
        try:

            buff = decrypt_message(client.recv(100), session_key)
            message = decrypt_message(client.recv(int(buff)), session_key)
            split = message.split('<>')
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
            
            elif split[0] == '™╣¶':
                remove_friend(split[1], split[2])
                query = encrypt_message('removed', session_key)
                client.send(encrypt_message(str(len(query)), session_key))
                client.send(query)

            elif split[0] == 'ø∞ö':
                query = encrypt_message(get_friends(split[1]), session_key)
                client.send(encrypt_message(str(len(query)), session_key))
                client.send(query)

            elif split[0] == 'ƒ₧—©±°◙':
                f = open(f"files\\{str(split[1])}", 'wb')
                while True:
                    buff = decrypt_message(client.recv(100), session_key)
                    if buff == '-1':
                        break
                    data = decrypt_file(client.recv(int(buff)), session_key)
                    f.write(data)
                f.close()
                #client.send(encrypt_message(f'{split[1]} uploaded successfully'))*******

            else:
                if split[1] == 'public':
                    public.append((client, v[1], session_key))
                broadcast(split[2], split[1], client)
        except Exception as e:
            print(e)
            print(str(addr) + ' disconnected')
            clients.remove((client, v[1], session_key))
            try:
                public.remove((client, v[1], session_key))
            except:
                pass
            client.close()
            broadcast(f'{v[1]} disconnected', client)
            break


def receive():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, 5554))
    s.listen(9)
    while True:
        c, addr = s.accept()
        print(f'[{time.strftime("%Y-%m-%d %H:%M:%S",time.localtime())}] connected with {str(addr)}')

        session_key = generate_key()

        thread = threading.Thread(target=handle, args=(c, addr, session_key))
        thread.start()

receive()
