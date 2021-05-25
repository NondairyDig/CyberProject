import socket
import threading
from zlib import decompress
from zlib import compress
from cv2 import *
from PIL import Image
import rsa
from mss import mss
from hashlib import sha3_256
import time
from cryptography.fernet import *


class User:
    def __init__(self, emailname, password, user_socket, nickname='', fr_list=''): #, email_socket_udp):

        self.nick = str(nickname) #  nickname(emailname)
        p = sha3_256() # setting up the module
        p.update(password.encode())
        self.pass_ = p.digest() #  password hash
        self.email = emailname.encode() # email
        self.client = user_socket
        self.f_list = fr_list
        #self.fast = email_socket_udp

    def login(self):
        try:
            self.client.send('L'.encode())
            n = int(self.client.recv(154).decode())
            e = int(self.client.recv(5).decode())
            pub = rsa.key.PublicKey(n, e)
            time.sleep(0.2)
            self.client.send(rsa.encrypt(self.email, pub))
            time.sleep(0.1)
            self.client.send(rsa.encrypt(self.pass_, pub))
            (pubu, priva) = rsa.newkeys(511)
            self.client.send(str(pubu.n).encode())
            self.client.send(str(pubu.e).encode())
            time.sleep(0.2)
            a = self.client.recv(64)
            m = rsa.decrypt(a, priva)
            time.sleep(0.2)
            p_comp = sha3_256()
            p_comp.update(self.pass_ + self.email)
            if m != p_comp.digest() + b'auth':
                self.client.close()
                return False
            else:
                ses = self.client.recv(64)
                sesd = rsa.decrypt(ses, priva)
                fff = self.client.recv(64)
                self.nick = rsa.decrypt(fff, priva).decode()
                return sesd
        except Exception as e:
            print(e)
            exit()

    def signup(self):
        time.sleep(1)
        self.client.send('S'.encode())
        n = int(self.client.recv(154).decode())
        e = int(self.client.recv(5).decode())
        pub = rsa.key.PublicKey(n, e)
        self.client.send(rsa.encrypt(self.email, pub))
        self.client.send(rsa.encrypt(self.pass_, pub))
        self.client.send(rsa.encrypt(self.nick.encode(), pub))
        time.sleep(0.5)
        (pub, priv) = rsa.newkeys(511)
        self.client.send(str(pub.n).encode())
        self.client.send(str(pub.e).encode())
        a = self.client.recv(64)
        s = rsa.decrypt(a, priv).decode()
        if s == 'fialad':
            print(s)
            return False
        else:
            return True

    def decrypt_message(self, encrypted_message, key):
        f = Fernet(key)
        decrypted_message = f.decrypt(encrypted_message)
        return decrypted_message.decode()

    def verify(self):
        self.client.send('V'.encode())
        time.sleep(0.3)
        message = 'ö∞øⁿŒç¼•¥Ωü§◙±©'.encode() 
        n = int(self.client.recv(154).decode())
        e = int(self.client.recv(5).decode())
        pubkey = rsa.key.PublicKey(n, e)
        signature = self.client.recv(64)
        rsa.verify(message, signature, pubkey)
        time.sleep(0.5)
        (pubkey, privkey) = rsa.newkeys(511)
        n = pubkey.n
        e = pubkey.e
        message = '©±°◙§≡üΩ¥•¼·ëçŒ▓ⁿø∞ö'.encode()
        signaturev = rsa.sign(message, privkey, 'SHA-1')
        self.client.send(str(n).encode())
        self.client.send(str(e).encode())
        self.client.send(signaturev)

    def update_f_list(self, friends):
        self.f_list = friends.split('-')

    def recvall(self, length):
        #Retrieve all pixels
        buffer = b''
        while len(buffer) < length:
            data = self.client.recv(length - len(buffer))
            if not data:
                return data
            buffer += data
        return buffer
    
"""def show_screen(self):
        pygame.init()
        pygame.display.set_caption('Screen Share')
        screen = pygame.display.set_mode((2560, 1440))
        clock = pygame.time.Clock()
        watching = True
        try:
            while watching:
                for event in pygame.event.get():
                    if event.type == pygame.QUIT:
                        watching = False
                        break

                # Retrieve the size of the pixels length, the pixels length and pixels
                size_len = int.from_bytes(self.client.recv(1), byteorder='big')
                size = int.from_bytes(self.client.recv(size_len), byteorder='big')
                pixels = decompress(self.recvall(self.client, size))

                img = pygame.image.fromstring(pixels, (2560, 1440), 'RGB')
                screen.blit(img, (0, 0))
                pygame.display.flip()
                clock.tick(60)
        finally:
            print('An error occurred')

    def show_webcam(self):
        pygame.init()
        pygame.display.set_caption('Camera')
        clock = pygame.time.Clock()
        watching = True
        try:
            while watching:
                for event in pygame.event.get():
                    if event.type == pygame.QUIT:
                        watching = False
                        break

                # Retrieve the size of the pixels length, the pixels length and pixels
                size_len = int.from_bytes(self.client.recv(1), byteorder='big')
                size = int.from_bytes(self.client.recv(size_len), byteorder='big')
                pixels = decompress(self.recvall(size))
                ff = open('cache\\WebCamCacheC.jpg', 'wb')
                ff.write(pixels)
                ff.close()
                i = Image.open('cache\\WebCamCacheC.jpg')
                screen = pygame.display.set_mode((i.size))
                img = pygame.image.load('cache\\WebCamCacheC.jpg')
                screen.blit(img, (0, 0))
                pygame.display.flip()
                clock.tick(60)
        finally:
            pygame.display.quit()

    def send_screenshot(self):
        # initialize the camera
        cam = VideoCapture(0)
        while 'recording':
            s, img = cam.read()  # get frame84
            imwrite("cache\\WebCamCacheS.jpg", img)  # save image
            f = open('cache\\WebCamCacheS.jpg', 'rb')
            data = compress(f.read(), 6)

            # Send the size of the pixels length
            size = len(data)
            size_len = (size.bit_length() + 7) // 8
            self.client.send(bytes([size_len]))

            # Send the actual pixels length
            size_bytes = size.to_bytes(size_len, 'big')
            self.client.send(size_bytes)

            # Send pixels
            self.client.sendall(data)



    def screenshot(self):
        with mss() as sct:
            # The region to capture
            rect = {'top': 0, 'left': 0, 'width': 2560, 'height': 1440}

            while 'recording':
                # Capture the screen
                img = sct.grab(rect)
                data = compress(img.rgb, 6)

                # Send the size of the pixels length
                size = len(data)
                size_len = (size.bit_length() + 7) // 8
                self.client.send(bytes([size_len]))

                # Send the actual pixels length
                size_bytes = size.to_bytes(size_len, 'big')
                self.client.send(size_bytes)

                # Send pixels
                self.client.sendall(data)"""