from kivy import Config
from kivy.core import text
from kivy.uix.floatlayout import FloatLayout
Config.set('graphics', 'width', '1200')
Config.set('graphics', 'height', '800')
Config.set('graphics', 'minimum_width', '800')
Config.set('graphics', 'minimum_height', '600')
Config.set('graphics', 'maximum_height', '2160')
Config.set('graphics', 'maximum_width', '3840')
Config.set('graphics', 'maxfps', 240)
Config.set('input', 'mouse', 'mouse,multitouch_on_demand')
Config.set('kivy', 'default_font', ['Arial', 'files/arial.ttf'])
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.uix.button import Button
from kivy.lang import Builder
from kivy.app import App
from kivy.uix.screenmanager import ScreenManager, Screen
from cryptography.fernet import Fernet
import socket
import threading
import re
import time
from kivy.properties import ObjectProperty
from User import User
from tkinter import filedialog
from tkinter import Tk
import os
import pyaudio
import cv2


"""udp, notifications""" # to-do list
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # global variable for socket
logged_in = False  # global variable for checking if log in is approved
skey = b''  # global variable for session key
user = '' #  global variable for user
nickname = ''  # global variable for user nickname
file_key = b'K4a6Y7CA8JZMNTTv8-XeSbX8BT3ywLmtz177ry11d0o='  # key to decrypt data file
host = '192.168.1.254'  # server address
special = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
special_vid = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
p = pyaudio.PyAudio()
stream = p.open(format=pyaudio.paInt16, channels=1, rate=24000, output=True)
stream_rec = p.open(format=pyaudio.paInt16, channels=1, rate=24000, input=True,
                        frames_per_buffer=1024)

def decrypt_message(encrypted_message, key): #  decrypt a message using Fernet module
    f = Fernet(key) #  initialize module in parameter
    decrypted_message = f.decrypt(encrypted_message) # decrypt the message
    return decrypted_message.decode() #  return the decrypted message as plain text


def encrypt_message(message, key): # a function to encrypt a message
    encoded_message = message.encode() # encode the message (module recievs only bytes)
    f = Fernet(key) #  initiate the module
    encrypted_message = f.encrypt(encoded_message) #  encrypt the message
    return encrypted_message #  return the encrypted message


def encrypt_file(file, key): #  a function for encrypting a file( a message in binary)
    f = Fernet(key)
    encrypted_file = f.encrypt(file)
    return encrypted_file


def decrypt_file(encrypted_file, key): #  a function for decrypting a file( a message in binary)
    f = Fernet(key)
    decrypted_file = f.decrypt(encrypted_file)
    return decrypted_file


def invalidUsername(): #  a function of notifieng if the username entered is not valid
    pop = Popup(title='Invalid Username',
                  content=Label(text='username needs to contain only numbers and letters if empty, please enter username.'),
                  size_hint=(None, None), size=(400, 400))
    pop.open()

def invalidPassword(): #  a function of notifieng if the password entered is not valid
    pop = Popup(title='Invalid Password',
                  content=Label(text='Password needs to be at between 7 and 35 charachters long.'),
                  size_hint=(None, None), size=(400, 400))

    pop.open()

def invalidEmail(): #  a function of what to do if the email entered is not valid
    pop = Popup(title='Invalid Email',
                  content=Label(text='Please Re-enter Email'),
                  size_hint=(None, None), size=(400, 400))
    pop.content.text = "bruh"
    pop.open()


class CreateAccountWindow(Screen): # a screen class of the sign up screen(needed for kivy(GUI))
    username = ObjectProperty(None)
    email = ObjectProperty(None)
    password = ObjectProperty(None)
    btn = ObjectProperty(None)
    pop = Popup(title='Status', auto_dismiss=False,
                  content=Label(text='Connecting...'),
                  size_hint=(None, None), size=(250, 100))

    def submit(self): #  a function that is called by a submit/sign-up button to check the validty the entered information
        s_username = self.username.text
        s_email = self.email.text
        s_password = self.password.text
        self.pop.open()
        if len(s_username) < 1 or s_username.isalnum() == False or ' ' in s_username:
            invalidUsername()
            self.email.text = ""
            self.password.text = ""
            self.username.text = ""
            return

        if len(s_email) < 8 or not re.search('^(\w|\.|\_|\-)+[@](\w|\_|\-|\.)+[.]\w{2,3}$', str(s_email)) or not s_email.split('@')[0].isalnum() or not s_email.split('@')[1].split('.')[0].isalnum() or not s_email.split('@')[1].split('.')[1].isalnum() or ' ' in s_email or s_email.count('@') > 1 or s_email.count('.') > 1:
            invalidEmail()
            self.email.text = ""
            self.password.text = ""
            self.username.text = ""
            return

        if len(s_password) < 7 or len(s_password) > 36:
            invalidPassword()
            self.email.text = ""
            self.password.text = ""
            self.username.text = ""
            return
        else:
            s_t = threading.Thread(target=self.signup, args=(s_email, s_password, s_username))
            s_t.start()
    
    def signup(self, e, p, n): # signing up function
        self.btn.disabled = True
        self.pop.content.text = 'Connecting...'
        self.pop.open()
        global client
        global skey
        global nickname
        nickname = n
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client.connect((host, 5554))
        except:
            self.btn.disabled = False
            self.pop.content.text = 'Couldn\'t connect to server'
            time.sleep(1)
            self.pop.dismiss()
            return
        global user
        user = User(e, p, client, n)
        try:
            self.pop.content.text = ('Verifying connection...')
            user.verify()
        except:
            self.btn.disabled = False
            self.pop.content.text = 'could not verify'
            time.sleep(1)
            self.pop.dismiss()
            return
        self.pop.content.text = 'Signing Up...' 
        if (user.signup()):
            self.pop.content.text = 'Logging In...'
            skey = user.login()
            if skey and skey != 'imp':
                self.btn.disabled = False
                self.pop.dismiss()
                client.send('im ready'.encode())
                sm.current = 'friends'
                sm.current_screen.load()
                return
            elif skey == 'imp':
                self.btn.disabled = False
                self.pop.content.text = 'Account Already Logged In'
                time.sleep(1)
                self.pop.dismiss()
                return
            else:
                self.btn.disabled = False
                self.pop.content.text = 'There was a problem logging in please try to logging in with your credentials or signing up again'
                time.sleep(1)
                self.pop.dismiss()
                return
        else:
            self.pop.content.text = 'Email or Username already exists'
            self.btn.disabled = False
            time.sleep(1)
            self.pop.dismiss()
            return  # ƒ₧—éè╣¶█©±°◙§≡üΩ¥•¼·ëçŒ▓ⁿø∞ö™
    
    def login(self): # go to login screen
        self.email.text = ""
        self.password.text = ""
        self.username.text = ""
        sm.current = "login"


class LoginWindow(Screen): 
    password = ObjectProperty(None)
    email = ObjectProperty(None)
    cb = ObjectProperty(None)
    btn = ObjectProperty(None)
    pop = Popup(title='Status',auto_dismiss= False,
                  content=Label(text='Connecting...'),
                  size_hint=(None, None), size=(250, 100))

    def kook(self): # check for "cookie"
        try:
            cookie = open('UserData.txt', 'rb')
            r = decrypt_message(cookie.read(), file_key).split('  ')
            if r[0] == str(b'YEs'):
                s_email = r[1]
                s_password = r[2]
                self.email.text = str(s_email)
                self.password.text = str(s_password)
                self.btn.trigger_action()
        except:
            pass

    def createBtn(self): # go to sign up screen
        self.email.text = ""
        self.password.text = ""
        sm.current = "create"
    
    def loginBtn(self): # cerdentials checking
        s_email = self.email.text
        s_password = self.password.text
        if len(s_email) < 8 or not re.search('^(\w|\.|\_|\-)+[@](\w|\_|\-|\.)+[.]\w{2,3}$', str(s_email)) or not s_email.split('@')[0].isalnum() or not s_email.split('@')[1].split('.')[0].isalnum() or not s_email.split('@')[1].split('.')[1].isalnum() or ' ' in s_email or s_email.count('@') > 1 or s_email.count('.') > 1:
            invalidEmail()
            self.email.text = ""
            self.password.text = ""
            return
        
        if len(s_password) < 7 or len(s_password) > 35:
            invalidPassword()
            self.email.text = ""
            self.password.text = ""
            self.username.text = ""
            return
        else:
            l_t = threading.Thread(target=self.login, args=(s_email, s_password,))
            l_t.start()
    
    def login(self, e, p): # logging in function
        self.btn.disabled = True
        self.pop.content.text = 'Connecting...'
        self.pop.open()
        global client
        global skey
        global nickname
        try:
            client.connect((host, 5554))
        except:
            self.btn.disabled = False
            self.pop.content.text = 'Couldn\'t connect to server'
            time.sleep(1)
            self.pop.dismiss()
            return
        global user
        user = User(str(e), str(p), client)
        try:
            self.pop.content.text = 'Verifying connection...'
            user.verify()
        except:
            self.pop.content.text = 'could not verify'
            self.btn.disabled = False
            time.sleep(1)
            self.pop.dismiss()
            return
        self.pop.content.text = 'Logging In...'
        skey = user.login()
        time.sleep(0.5)
        nickname = user.nick
        if skey and skey != 'imp':
            if self.cb.active:
                f = open('UserData.txt', 'wb')
                f.write(encrypt_message(str('YEs'.encode()) + '  ' + str(e) + '  ' + str(p), file_key))
                f.close()
            self.btn.disabled = False
            client.send('im ready'.encode())
            self.pop.dismiss()
            sm.current = 'friends'
            sm.current_screen.load()
            return
        elif skey == 'imp':
            self.btn.disabled = False
            self.pop.content.text = 'Account Already Logged In'
            time.sleep(1)
            self.pop.dismiss()
            f = open('UserData.txt', 'wb')
            f.write(b'')
            f.close()
            return
        else:
            self.btn.disabled = False
            self.pop.content.text = 'Wrong login'
            time.sleep(1)
            self.pop.dismiss()
            return


class MainWindow(Screen):
    tb = ObjectProperty(None) #  text browser
    mtb = ObjectProperty(None) #  main text browser (for writing)
    gx = ObjectProperty(None) # gridlayout of files
    up = ObjectProperty(None) # upload file button
    vo = ObjectProperty(None) # join voice button
    vi = ObjectProperty(None) # start stream button
    fl = ObjectProperty(None) # float layout of screen
    jo = ObjectProperty(None) # host video button
    pop = Popup(title='Status',auto_dismiss= False,
                  content=Label(text='Adding friend...'),
                  size_hint=(None, None), size=(250, 100))

    def getfile(self, b): # a function to pick a directory to store the picked file
        Tk().withdraw() #  dismiss the main screen
        pathname = filedialog.askdirectory() #  get save path
        if pathname == '':
            return
        query = encrypt_message('▓quitf', skey)
        client.send(encrypt_message(str(len(query)), skey))
        client.send(query)
        f_t = threading.Thread(target=self.getfile_main, args=(b, pathname))
        f_t.start()

    def getfile_main(self, b, d): # a function called to a thread to get/download a picked file to the server
        try:
            file = open(str(d) + '\\'+ str(b.text), 'ab')
            self.pop.content.text = "Getting file..."
            self.pop.open()
            query = encrypt_message(f'◙°±©—₧ƒ<>{b.text}<>{user.nick}', skey)
            client.send(encrypt_message(str(len(query)), skey))
            client.send(query)
            data = ''
            while True:
                buff = decrypt_message(client.recv(100), skey)
                if buff == '-1' or data == b'-1':
                    break
                data = decrypt_file(client.recv(int(buff)), skey)
                file.write(data)
            self.pop.content.text = "File Received"
            time.sleep(1)
            self.pop.dismiss()
            self.receive()
            return
        except Exception as e:
            print(e)
            self.pop.content.text = 'An error occurd please wait or restart the app'
            self.pop.open()
            time.sleep(1)
            self.pop.dismiss()
            self.receive()
            return
    
    def send_voice(self): # a function to send voice recordings
        time.sleep(0.1)
        while True:
            try:
                special.send(encrypt_file(stream_rec.read(1024), skey))
            except:
                self.vo.disabled = False
                special.close()
                self.pop.open()
                self.pop.content.text = "Disconnected from voice"
                time.sleep(1)
                self.pop.dismiss()
                return

    def leave_voice(self, b): # leave the voice chat
        self.vo.disabled = False
        special.close()
        self.fl.remove_widget(b)

    def voice_main(self): # main voice function
        vkey = b'JlIw6uoJknefy2pI7nzTyb8fnzdewdtqpVrk7AYYxWE='
        try:
            special.connect((host, 61441))
            query = encrypt_message(str(user.nick), vkey)
            special.send(encrypt_message(str(len(query)), vkey))
            special.send(query)

            query = encrypt_message(f'con<>{target}<>{user.nick}', skey)
            special.send(encrypt_message(str(len(query)), skey))
            special.send(query)
            an = special.recv(5)
            if an != 'start'.encode():
                return
            time.sleep(0.1)
            self.fl.add_widget(Button(text='Leave Voice', pos_hint={"x":0.88, "y": 0.24}, size_hint=(0.1, 0.05), on_release=self.leave_voice))
            mv_t = threading.Thread(target=self.send_voice)
            mv_t.start()
            while True:
                data = decrypt_file(special.recv(2828), skey)
                stream.write(data)
        except:
            self.vo.disabled = False
            special.close()
            self.pop.open()
            self.pop.content.text = "Disconnected from voice"
            time.sleep(1)
            self.pop.dismiss()

    def voice(self): # starting voice communication thread
        self.vo.disabled = True
        v_t = threading.Thread(target=self.voice_main)
        v_t.start()

    def send_video(self): # a function to send voice recordings
        time.sleep(0.1)
        feed = cv2.VideoCapture(0)
        while True:
            try:
                cv2.imwrite('cache\\WebCamCacheS.jpg', feed.read()[1])
            except:
                continue
            try:
                f = open('cache\\WebCamCacheS.jpg', 'rb')
                query = encrypt_file(f.read(), skey)
                special_vid.send(encrypt_message(str(len(query)), skey))
                special_vid.send(query)
                f.close()
            except:
                break
        feed.release()
        special_vid.close()
        self.pop.open()
        self.pop.content.text = "Disconnected from video"
        time.sleep(1)
        self.pop.dismiss()
        return
            

    def join_vid(self): # joining video thread
        vidd_t = threading.Thread(target=self.join_vid_main)
        vidd_t.start()

    def join_vid_main(self): # joining video stream of someone else
        self.jo.disabled = True
        self.vi.disabled = True
        vkey = b'JlIw6uoJknefy2pI7nzTyb8fnzdewdtqpVrk7AYYxWE='
        special_vid.connect((host, 14655))
    
        query = encrypt_message(user.nick, vkey)
        special_vid.send(encrypt_message(str(len(query)), vkey))
        special_vid.send(query)

        query = encrypt_message(f'con<>{target}<>{user.nick}<>recv', skey)
        special_vid.send(encrypt_message(str(len(query)), skey))
        special_vid.send(query)

        try:
            while True:
                buff = decrypt_message(special_vid.recv(100), skey)
                message = decrypt_file(special_vid.recv(int(buff)), skey)
                f = open('cache\\WebCamCacheC.jpg', 'wb')
                f.write(message)
                f.close()
                try:
                    img = cv2.imread('cache\\WebCamCacheC.jpg')
                    cv2.imshow('press q to exit', img)
                except:
                    if cv2.waitKey(1) & 0xFF == ord('q'):
                        break
                    continue
                if cv2.waitKey(1) & 0xFF == ord('q'):
                    break
            self.jo.disabled = False
            self.vi.disabled = False
            special_vid.close()
            self.pop.open()
            self.pop.content.text = "Disconnected from video"
            time.sleep(1)
            self.pop.dismiss()
            return
        except:
            pass
        self.jo.disabled = False
        self.vi.disabled = False
        special_vid.close()
        self.pop.open()
        self.pop.contenttext = "Disconnected from video"
        time.sleep(1)
        self.pop.dismiss()
        return

    def leave_video(self, b): # quit the video stream
        special_vid.close()
        self.fl.remove_widget(b)
        self.jo.disabled = False
        self.vi.disabled = False

    def video_main(self): # main video function
        vkey = b'JlIw6uoJknefy2pI7nzTyb8fnzdewdtqpVrk7AYYxWE='
        try:
            special_vid.connect((host, 14655))

            query = encrypt_message(user.nick, vkey)
            special_vid.send(encrypt_message(str(len(query)), vkey))
            special_vid.send(query)

            query = encrypt_message(f'con<>{target}<>{user.nick}<>host', skey)
            special_vid.send(encrypt_message(str(len(query)), skey))
            special_vid.send(query)

            an = special_vid.recv(5)
            if an != 'start'.encode():
                return
            time.sleep(0.1)
            self.fl.add_widget(Button(text='Stop Video', pos_hint={"x":0.88, "y": 0.42}, size_hint=(0.1, 0.05), on_release=self.leave_video))
            mvid_t = threading.Thread(target=self.send_video)
            mvid_t.start()
        except Exception as e:
            self.jo.disabled = False
            self.vi.disabled = False
            print(e)
            special_vid.close()
            self.pop.open()
            self.pop.content.text = "Disconnected from video"
            time.sleep(1)
            self.pop.dismiss()
            return

    def video(self): # start streaming camera thread
        self.jo.disabled = True
        self.vi.disabled = True
        vi_t = threading.Thread(target=self.video_main)
        vi_t.start()
        

    def load(self): # a function to load files
        global target
        self.gx.bind(minimum_height=self.gx.setter('height')) #  adapt layout size
        query = encrypt_message(f'₧ƒ<>{user.nick}<>{target}', skey)
        client.send(encrypt_message(str(len(query)), skey))
        client.send(query)
        length = decrypt_message(client.recv(100), skey)
        filelist = decrypt_message(client.recv(int(length)), skey).split('-') #  get fileist from server and sort it
        check = False #  set a variable for checking duplicates
        if filelist != ['']: #  check if filelist is not empty
            for file in filelist: #  go over recived filelist
                for obj in self.gx.children: #  go over the existing widgets in layout
                    if file == obj.text: #  check if button already exiest for file
                        check = True # if found duplicate let the program know 
                        break #  end the inside loop
                if file != '' and not check: #  if file is not nothing and his duplicate not found
                    self.gx.add_widget(Button(text=file, on_release=self.getfile)) #  add button to friend
                check = False #  reset the duplicate checking variable
        query = encrypt_message(f'§≡üΩ¥•¼<>{target}<>{user.nick}', skey)
        client.send(encrypt_message(str(len(query)), skey))
        client.send(query)
        length = decrypt_message(client.recv(100), skey)
        history = decrypt_message(client.recv(int(length)), skey)
        self.tb.text = history

    def write(self): # a function that writes to the server a message to send to the target
        self.mtb.focus = True
        if not str(self.mtb.text).isspace() and str(self.mtb.text) != '' and len(str(self.mtb.text)) < 1000 :
            message = f'{nickname}: {self.mtb.text}'
            t = self.tb.text
            self.tb.text = str(t) + str(message) + '\r\n'
            self.mtb.text = ''
            try:
                global target
                query = encrypt_message('▓<>' + target + '<>' + message, skey)
                client.send(encrypt_message(str(len(query)), skey))
                client.send(query)
            except Exception as e:
                print(e)
                t = self.tb.text
                self.tb.text =  str(t) + f'couldn\'t send message please try again or restart the app\r\n'
        elif len(str(self.mtb.text)) < 1000:
            t = self.tb.text
            self.tb.text = t + '\r\nCant be empty or longer than 999 chars'

    def limit(self): #  called when text is inputed to check if the message is not greater then 1000 words
        if len(str(self.mtb.text)) > 1000:
            t = self.mtb.text
            self.mtb.text = ''
            self.mtb.text = t

    def send_file(self, f, t): # a functions called to a thread to upload a file to the server
        if f != '':
            p = str(f.split('/')[-1])
            file = open(str(f), 'rb')
            query = encrypt_message(f'ƒ₧—©±°◙<>{p}<>{t}', skey)
            length = encrypt_message(str(len(query)), skey)
            client.send(length)
            client.send(query)
            while True:
                data = file.read(1024)
                if data == b'':
                    file.close()
                    client.send(encrypt_message('-1', skey))
                    break
                query = encrypt_file(data, skey)
                client.send(encrypt_message(str(len(query)), skey))
                client.send(query)
                time.sleep(0.0000000001)
            buff = decrypt_message(client.recv(100), skey)
            ans = decrypt_message(client.recv(int(buff)), skey)
            if ans == 'uploaded successfully©◙ƒ<>':
                    self.pop.content.text = 'Uploaded file'
                    self.pop.open()
                    time.sleep(1)
                    self.pop.dismiss()
                    self.load()
                    self.receive()
                    return
            else:
                self.pop.content.text = 'Uploading file failed'
                self.pop.open()
                time.sleep(1)
                self.pop.dismiss()
                self.load()
                self.receive()
                return
        else:
            return

    def sendFile(self): # a function to pick a file and start a thread to upload it
        Tk().withdraw() #  dismiss the main screen
        filename = filedialog.askopenfilename() #  get picked file path
        if filename != '':
            if int(os.path.getsize(filename)) < 10000000: #  limit file size to 10 MB
                query = encrypt_message('▓quitf', skey)
                client.send(encrypt_message(str(len(query)), skey))
                client.send(query)
                self.pop.content.text = "Uploading file..."
                self.pop.open()
                file_thread = threading.Thread(target=self.send_file, args=(filename, target))
                file_thread.start()
        else:
            self.pop.content.text = "File is too large"
            self.pop.open()
            time.sleep(1)
            self.pop.dismiss()

    def receive_main(self): #  a function called to a thread to recieve message while in chat
        while True:
            try:
                buff = decrypt_message(client.recv(100), skey)
                message = decrypt_message(client.recv(int(buff)), skey)
                k = message.split('<>')
                if k[0] == 'byebye±°':
                    special.close()
                    query = encrypt_message(f'Ω¥•¼<>', skey)
                    client.send(encrypt_message(str(len(query)), skey))
                    client.send(query)
                    sm.current = "friends"
                    sm.current_screen.load()
                    return

                if k[0] == 'filing±°':
                    return

                else:
                    t = self.tb.text
                    self.tb.text = t + k[0] + '\r\n'

            except Exception as e:
                self.pop.content.text = 'An error occurred please wait or restart the app'
                self.pop.open()
                time.sleep(1)
                self.pop.dismiss()
                sm.current = "friends"
                sm.current_screen.load()
                return

    def receive(self): # start receiving thread
        if target == 'public':
            self.vo.disabled = True
            self.up.disabled = True
            self.vi.disabled = True
            self.jo.disabled = True
        else:
            self.jo.disabled = False
            self.vo.disabled = False
            self.up.disabled = False
            self.vi.disabled = False
        r_t = threading.Thread(target=self.receive_main)
        r_t.start()

    def leave(self): # leave room thread(leave room button)
        l_t = threading.Thread(target=self.leave_main)
        l_t.start()

    def leave_main(self): # leave room function
        self.tb.text = ''
        global target
        query = encrypt_message(f'Ω¥•¼<>', skey)
        client.send(encrypt_message(str(len(query)), skey))
        client.send(query)
        if target == 'public':
            query = encrypt_message('t◙<>quit_pub', skey)
            client.send(encrypt_message(str(len(query)), skey))
            client.send(query)
        query = encrypt_message('▓quit<>', skey)
        client.send(encrypt_message(str(len(query)), skey))
        client.send(query)
        target = ''
        return


class FriendsScreen(Screen):
    bx = ObjectProperty(None)
    rq = ObjectProperty(None)

    def add_friend_screen(self): # go to add a friend screen
        sm.current = "addfriend"

    def public(self): # join public room
        global target
        target = 'public'
        query = encrypt_message(f'Ω¥•¼<>{target}', skey)
        client.send(encrypt_message(str(len(query)), skey))
        client.send(query)
        query = encrypt_message('t◙<>public', skey)
        client.send(encrypt_message(str(len(query)), skey))
        client.send(query)
        query = encrypt_message(f'§≡üΩ¥•¼<>public<>{user.nick}', skey)
        client.send(encrypt_message(str(len(query)), skey))
        client.send(query)
        sm.current = "main"
        sm.current_screen.receive()

    def load(self): # load list of friends
        self.bx.bind(minimum_height=self.bx.setter('height')) #  adapt layout size
        query = encrypt_message(f'ø∞ö<>{user.email.decode()}', skey)
        client.send(encrypt_message(str(len(query)), skey))
        client.send(query)
        length = decrypt_message(client.recv(100), skey)
        friendlist = sorted(decrypt_message(client.recv(int(length)), skey).split('-'), key=str.lower) #  get friendlist string from server make it a list and sort it
        check = False #  set a variable for checking duplicates
        if friendlist != ['']: #  check if friendlist is not empty
            for friend in friendlist: #  go over recived friendlist
                for obj in self.bx.children: #  go over the existing widgets in layout
                    if friend.split('(')[0] == obj.text.split('(')[0]:
                        obj.text = friend #  check if button already exiest for friend
                        check = True # if found duplicate let the program know
                        break #  end the inside loop for better runtime
                if friend.split('(')[0] != '' and not check: #  if friend is not nothing and his duplicate not found
                    self.bx.add_widget(Button(text=friend, on_release=self.start_private)) #  add button to friend
                check = False #  reset the duplicate checking variable
        query = encrypt_message(f'é<>{user.nick}', skey)
        client.send(encrypt_message(str(len(query)), skey))
        client.send(query)
        length = decrypt_message(client.recv(100), skey)
        number_of_requests = decrypt_message(client.recv(int(length)), skey)
        self.rq.text = f'Friend Requests ({str(number_of_requests)})'


    def start_private(self, button): # start private communications
        global target
        target = button.text.split('(')[0]
        query = encrypt_message(f'Ω¥•¼<>{target}', skey)
        client.send(encrypt_message(str(len(query)), skey))
        client.send(query)
        sm.current = "main"
        sm.current_screen.load()
        sm.current_screen.receive()

    def remove_friend(self): # got to remove a friend screen
        sm.current = "remove"
        sm.current_screen.load()
    
    def friend_requests(self): # go to friend requests screen
        sm.current = "requests"
        sm.current_screen.load()

    def logOut(self): #  log-out function
        client.close()
        try:
            delete = open('UserData.txt', 'wb') #  open "cookie" file
            delete.write(b'') #  reset the file
        except:
            pass
        exit() # quit application


class AddFriend(Screen):
    friend = ObjectProperty(None)
    pop = Popup(title='Status',auto_dismiss= False,
                  content=Label(text='Adding friend...'),
                  size_hint=(None, None), size=(250, 100))

    def add_friend(self): # start adding a friend thread
        af = threading.Thread(target=self.add_friend_main)
        af.start()
    
    def add_friend_main(self): # adding a friend function
        global user
        self.pop.content.text = 'Adding Friend...'
        self.pop.open()
        query = encrypt_message(f'üΩ¥<>{user.nick}<>{self.friend.text}' , skey)
        client.send(encrypt_message(str(len(query)), skey))
        client.send(query)
        length = decrypt_message(client.recv(100), skey)
        ans = decrypt_message(client.recv(int(length)), skey)
        if ans == 'added':
            self.pop.content.text = 'Friend request sent successfully'
            time.sleep(1)
            self.pop.dismiss()
            sm.current = "friends"
            sm.current_screen.load()
        else:
            self.pop.content.text = 'No such user found'
            self.pop.open()
            time.sleep(1)
            self.pop.dismiss()
        return
    
    def goBack(self): # go back to friends screen
        sm.current = "friends"
        sm.current_screen.load()


class RemoveFriend(Screen):
    bx = ObjectProperty(None) # id for a layout in kivy
    pop = Popup(title='Status',auto_dismiss= False, # create a popup
                  content=Label(text='Removing friend...'),
                  size_hint=(None, None), size=(250, 100))

    def back(self): # a method for the button of going back to the friends screen
        sm.current = "friends" #  go back to the friends screen
        sm.current_screen.load() #  call the loading friends method of the friends screen

    def load(self): # a method for loading the friendlist
        self.bx.bind(minimum_height=self.bx.setter('height')) #  adapt layout size
        query = encrypt_message(f'ø∞ö<>{user.email.decode()}', skey) #  send the required signal to the server
        client.send(encrypt_message(str(len(query)), skey)) #  send the length of the request to the server
        client.send(query) #  send the request to the server
        length = decrypt_message(client.recv(100), skey) #  get len of answer from server
        friendlist = decrypt_message(client.recv(int(length)), skey).split('-') #  get friendlist from server and sort it
        check = False #  set a variable for checking duplicates
        if friendlist != ['']: #  check if friendlist is not empty
            for friend in friendlist: #  go over recived friendlist
                for obj in self.bx.children: #  go over the existing widgets in layout
                    if friend == obj.text: #  check if button already exiest for friend
                        check = True # if found duplicate let the program know 
                        break #  end the inside loop for better runtime
                if friend.split('(')[0] != '' and not check: #  if friend is not nothing and his duplicate not found
                    self.bx.add_widget(Button(text=friend, on_release=self.remove_f)) #  add button to friend
                check = False #  reset the duplicate checking variable

    def remove_f(self, b): #  is getting the screen and button
        rf = threading.Thread(target=self.remove_f_main, args=(b,))
        rf.start()
    
    def remove_f_main(self, b): # main removing friend function
        global user #  get the global user variable
        self.pop.content.text = 'Removing friend...'
        self.pop.open()
        friend = b.text.split('(')[0]
        query = encrypt_message(f'™╣¶<>{user.email.decode()}<>{friend}' , skey)
        client.send(encrypt_message(str(len(query)), skey))
        client.send(query)
        length = decrypt_message(client.recv(100), skey)
        ans = decrypt_message(client.recv(int(length)), skey)
        if ans == 'removed':
            self.pop.content.text = 'Removed friend successfully'
            self.pop.open()
            self.bx.children.remove(b)
            time.sleep(1)
            self.pop.dismiss()
            sm.current = "friends"
            sm.current_screen.load()
        else:
            self.pop.content.text = 'An error occurred'
            self.pop.open()
            for obj in self.bx.children:
                if obj.text == b.text:
                    place = self.bx.children.index(obj)
                    self.bx.children[place].remove()
            time.sleep(1)
            self.pop.dismiss()
            sm.current = "friends"
            sm.current_screen.load()
        return


class Requests(Screen):
    bx = ObjectProperty(None)
    pop = Popup(title='Status',auto_dismiss= False, # create a popup
                  content=Label(text='Friend'),
                  size_hint=(None, None), size=(250, 100))
    
    def back(self): # go back to friend screen
        sm.current = "friends"
        sm.current_screen.load()

    def load(self): # a method for loading the friend requests
        self.bx.bind(minimum_height=self.bx.setter('height')) #  adapt layout size
        query = encrypt_message(f'₧—é<>{user.nick}<>', skey) #  send the required signal to the server
        client.send(encrypt_message(str(len(query)), skey)) #  send the length of the request to the server
        client.send(query) #  send the request to the server
        length = decrypt_message(client.recv(100), skey) #  get len of answer from server
        requests = decrypt_message(client.recv(int(length)), skey).split('-') #  get friendlist from server and sort it
        check = False #  set a variable for checking duplicates
        if requests != ['']: #  check if requests are not empty
            for request in requests: #  go over recived requests
                for obj in self.bx.children: #  go over the existing widgets in layout
                    if request == obj.text + ':': #  check if request already exiests
                        check = True # if found duplicate let the program know 
                        break #  end the inside loop for better runtime
                if request != '' and not check: #  if request is not nothing and its duplicate not found
                    self.bx.add_widget(Label(text=(request + ':')))
                    self.bx.add_widget(Button(text=('accept ' + request), on_release=self.accept_reject)) #  add button to accept
                    self.bx.add_widget(Button(text=('reject ' + request), on_release=self.accept_reject)) #  add button to reject
                check = False #  reset the duplicate checking variable

    def accept_reject(self, b): # accept\reject thread
        ar = threading.Thread(target=self.accept_reject_main, args=(b,))
        ar.start()

    def accept_reject_main(self, b): # main function to accept\reject friend request
        ans = b.text.split(' ')
        if ans[0] == 'accept':
            query = encrypt_message(f'éè╣<>accept<>{user.nick}<>{ans[1]}', skey) #  send the required signal to the server
            client.send(encrypt_message(str(len(query)), skey)) #  send the length of the request to the server
            client.send(query) #  send the request to the server
            for obj in self.bx.children:
                if obj.text == ans[1]:
                    place = self.bx.children.index(obj)
                    self.bx.children[place].remove()
                    self.bx.children[place + 1].remove()
                    self.bx.children[place + 2].remove()
            sm.current = 'friends'
            sm.current_screen.load()

        elif ans[0] == 'reject':
            query = encrypt_message(f'éè╣<>reject<>{user.nick}<>{ans[1]}', skey) #  send the required signal to the server
            client.send(encrypt_message(str(len(query)), skey)) #  send the length of the request to the server
            client.send(query) #  send the request to the server
            for obj in self.bx.children:
                if obj.text == ans[1]:
                    place = self.bx.children.index(obj)
                    self.bx.children[place].remove()
                    self.bx.children[place + 1].remove()
                    self.bx.children[place + 2].remove()
            sm.current == 'friends'
            sm.current_screen.load()
        return


class WindowManager(ScreenManager):
    pass


#  start of pre-load operation
kv = Builder.load_file("SSS.kv")
sm = WindowManager()

screens = [Requests(name="requests") ,AddFriend(name="addfriend"), LoginWindow(name="login"), CreateAccountWindow(name="create"),MainWindow(name="main"), FriendsScreen(name="friends"), RemoveFriend(name="remove")]
for screen in screens:
    sm.add_widget(screen)

sm.current = "login" #  start from log-in window
sm.current_screen.kook() #  check for automatic log-in with the kook() function


class SSS(App):
    def build(self):
        return sm #  return the screen manager, type: WindowManager

if __name__ == "__main__":
    SSS().run() #  run GUI
    try:
        global target
        if target == 'public':
            query = encrypt_message('t◙<>quit_pub', skey)
            client.send(encrypt_message(str(len(query)), skey))
            client.send(query)
        query = encrypt_message('▓quit<>' + target + '<>' + f'{user.nick} left the room', skey)
        client.send(encrypt_message(str(len(query)), skey))
        client.send(query)
        client.close()
        exit()
    except:
        pass