import rsa
from hashlib import sha3_256
import time
from cryptography.fernet import *


class User:
    def __init__(self, emailname, password, user_socket, nickname=''): #, email_socket_udp):

        self.nick = str(nickname) #  nickname(emailname)
        p = sha3_256() # setting up the module
        p.update(password.encode())
        self.pass_ = p.digest() #  password hash
        self.email = emailname.encode() # email
        self.client = user_socket

    def login(self):
        self.client.send('L'.encode())
        n = int(self.client.recv(154).decode())
        e = int(self.client.recv(5).decode())
        pub = rsa.key.PublicKey(n, e)
        self.client.send(rsa.encrypt(b'e/\<>' + self.email, pub))
        time.sleep(0.1)
        self.client.send(rsa.encrypt(b'p/\<>' + self.pass_, pub))
        (pubu, priva) = rsa.newkeys(511)
        self.client.send(str(pubu.n).encode())
        self.client.send(str(pubu.e).encode())
        time.sleep(0.2)
        auth = self.client.recv(64)
        m = rsa.decrypt(auth, priva)
        time.sleep(0.2)
        p_comp = sha3_256()
        p_comp.update(self.pass_ + self.email)
        if m != p_comp.digest() + b'auth':
            if m == b'impost':
                return 'imp'
            else:
                self.client.close()
                return False
        else:
            ses = self.client.recv(64)
            sesd = rsa.decrypt(ses, priva)
            fff = self.client.recv(64)
            self.nick = rsa.decrypt(fff, priva).decode()
            return sesd

    def signup(self):
        time.sleep(1)
        self.client.send('S'.encode())
        n = int(self.client.recv(154).decode())
        e = int(self.client.recv(5).decode())
        pub = rsa.key.PublicKey(n, e)
        self.client.send(rsa.encrypt(b'e/\<>' + self.email, pub))
        self.client.send(rsa.encrypt(b'p/\<>' + self.pass_, pub))
        self.client.send(rsa.encrypt(b'u/\<>' + self.nick.encode(), pub))
        time.sleep(0.2)
        (pub, priv) = rsa.newkeys(511)
        self.client.send(str(pub.n).encode())
        self.client.send(str(pub.e).encode())
        a = self.client.recv(64)
        s = rsa.decrypt(a, priv).decode()
        if s == 'fialad':
            return False
        else:
            return True

    def verify(self):
        self.client.send('V'.encode())
        time.sleep(0.3)
        message = '??????????????????????????????????'.encode() 
        n = int(self.client.recv(154).decode())
        e = int(self.client.recv(5).decode())
        pubkey = rsa.key.PublicKey(n, e)
        signature = self.client.recv(64)
        rsa.verify(message, signature, pubkey)
        time.sleep(0.5)
        (pubkey, privkey) = rsa.newkeys(511)
        n = pubkey.n
        e = pubkey.e
        message = '??????????????????????????????????????????????'.encode()
        signaturev = rsa.sign(message, privkey, 'SHA-1')
        self.client.send(str(n).encode())
        self.client.send(str(e).encode())
        self.client.send(signaturev)

    def recvall(self, length):
        #Retrieve all pixels
        buffer = b''
        while len(buffer) < length:
            data = self.client.recv(length - len(buffer))
            if not data:
                return data
            buffer += data
        return buffer
