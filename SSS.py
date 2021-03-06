from kivy import Config
Config.set('graphics', 'width', '854')
Config.set('graphics', 'height', '480')
Config.set('graphics', 'minimum_width', '854')
Config.set('graphics', 'minimum_height', '480')
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


#to-do: Video Transfer(Re-Emmbed), Notifications.
# ƒ₧—éè╣¶█©±°◙§≡üΩ¥•¼·ëçŒ▓ⁿø∞ö™
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # global variable for socket
skey = b''  # global variable for session key
user = '' #  global variable for user
file_key = b'K4a6Y7CA8JZMNTTv8-XeSbX8BT3ywLmtz177ry11d0o='  # key to decrypt data file
host = '10.203.1.254'  # server address
global special 
special = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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


def decrypt_file(encrypted_file, key): #  a function for decrypting a file(a message in binary)
    f = Fernet(key)
    decrypted_file = f.decrypt(encrypted_file)
    return decrypted_file

def invalidUsername(): #  a function of notifieng if the username entered is not valid
    pop = Popup(title='Invalid Username', auto_dismiss = False,
                  content=Label(text='username needs to contain only numbers and letters if empty, please enter username.'),
                  size_hint=(None, None), size=(400, 200))
    pop.open()
    time.sleep(2)
    pop.dismiss()

def invalidPassword(): #  a function of notifieng if the password entered is not valid
    pop = Popup(title='Invalid Password', auto_dismiss = False,
                  content=Label(text='Password needs to be at between 7 and 35 charachters long.'),
                  size_hint=(None, None), size=(400, 200))

    pop.open()
    time.sleep(2)
    pop.dismiss()

def invalidEmail(): #  a function of what to do if the email entered is not valid
    pop = Popup(title='Invalid Email', auto_dismiss = False,
                  content=Label(text='Email Doesn\'t Exists'),
                  size_hint=(None, None), size=(400, 200))
    pop.open()
    time.sleep(2)
    pop.dismiss()

def unmatchedPass():
    pop = Popup(title='Invalid Email', auto_dismiss = False,
                content=Label(text='Passwords Are Not Matched'),
                size_hint=(None, None), size=(400, 200))
    pop.open()
    time.sleep(2)
    pop.dismiss()

def error():
    pop = Popup(title='Error', auto_dismiss = False,
                  content=Label(text='There Was a problem connecting to server. try to refresh or restart'),
                  size_hint=(None, None), size=(500, 200))
    pop.open()
    time.sleep(2)
    pop.dismiss()

def largeFile():
    pop = Popup(title='Error', auto_dismiss = False,
                content=Label(text='File is to large and must be under 10MB'),
                size_hint=(None, None), size=(500, 200))
    pop.open()
    time.sleep(2)
    pop.dismiss()

def error_t():
    t = threading.Thread(target=error)
    t.start()


class CreateAccountWindow(Screen): # a screen class of the sign up screen(needed for kivy(GUI))
    username = ObjectProperty(None)
    email = ObjectProperty(None)
    password = ObjectProperty(None)
    password_con = ObjectProperty(None)
    btn = ObjectProperty(None)
    pop = Popup(title='Status', auto_dismiss=False,
                  content=Label(text='Connecting...'),
                  size_hint=(None, None), size=(250, 100))

    def submit(self): #  a function that is called by a submit/sign-up button to check the validty the entered information
        s_username = self.username.text
        s_email = self.email.text.lower()
        s_password = self.password.text
        s_password_confirm = self.password_con.text

        if len(s_username) < 4 or len(s_username) > 36 or s_username.isalnum() == False or ' ' in s_username:
            invalidUsername()
            self.email.text = ""
            self.password.text = ""
            self.username.text = ""
            self.password_con.text = ""
            return

        if len(s_email) < 8 or not re.search('^(\w|\.|\_|\-)+[@](\w|\_|\-|\.)+[.]\w{2,3}$', str(s_email)) or not s_email.split('@')[0].isalnum() or not s_email.split('@')[1].split('.')[0].isalnum() or not s_email.split('@')[1].split('.')[1].isalnum() or ' ' in s_email or s_email.count('@') > 1 or s_email.count('.') > 1:
            invalidEmail()
            self.email.text = ""
            self.password.text = ""
            self.username.text = ""
            self.password_con.text = ""
            return

        if len(s_password) < 7 or len(s_password) > 36:
            invalidPassword()
            self.email.text = ""
            self.password.text = ""
            self.username.text = ""
            self.password_con.text = ""
            return
        
        if s_password != s_password_confirm:
            unmatchedPass()
            self.email.text = ""
            self.password.text = ""
            self.username.text = ""
            self.password_con.text = ""
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
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client.connect((host, 5554))
        except:
            self.btn.disabled = False
            self.pop.content.text = 'Couldn\'t connect to server'
            time.sleep(2)
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
            time.sleep(2)
            self.pop.dismiss()
            return
        self.pop.content.text = 'Signing Up...' 
        if (user.signup()):
            self.pop.content.text = 'Logging In...'
            skey = user.login()
            if skey and skey != 'imp':
                self.btn.disabled = False
                self.pop.dismiss()
                sm.current = 'auth'
                return
            elif skey == 'imp':
                self.btn.disabled = False
                self.pop.content.text = 'Account Already Logged In'
                time.sleep(2)
                self.pop.dismiss()
                return
            else:
                self.btn.disabled = False
                self.pop.content.text = 'There was a problem logging in please try to logging in with your credentials or signing up again'
                time.sleep(2)
                self.pop.dismiss()
                return
        else:
            self.pop.content.text = 'Email Is Not Valid or Email or Username Already Exists'
            self.btn.disabled = False
            time.sleep(2)
            self.pop.dismiss()
            return
    
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
        s_email = self.email.text.lower()
        s_password = self.password.text
        if len(s_email) < 8 or not re.search('^(\w|\.|\_|\-)+[@](\w|\_|\-|\.)+[.]\w{2,3}$', str(s_email)) or not s_email.split('@')[0].isalnum() or not s_email.split('@')[1].split('.')[0].isalnum() or not s_email.split('@')[1].split('.')[1].isalnum() or ' ' in s_email or s_email.count('@') > 1 or s_email.count('.') > 1:
            invalidEmail()
            self.email.text = ""
            self.password.text = ""
            return
        
        if len(s_password) < 7 or len(s_password) > 35:
            invalidPassword()
            self.password.text = ""
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
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client.connect((host, 5554))
        except:
            self.btn.disabled = False
            self.pop.content.text = 'Couldn\'t connect to server'
            time.sleep(2)
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
            time.sleep(2)
            self.pop.dismiss()
            return
        self.pop.content.text = 'Logging In...'
        skey = user.login()
        time.sleep(0.5)
        if skey and skey != 'imp':
            if self.cb.active:
                f = open('UserData.txt', 'wb')
                f.write(encrypt_message(str('YEs'.encode()) + '  ' + str(e) + '  ' + str(p), file_key))
                f.close()
            self.btn.disabled = False
            self.pop.dismiss()
            sm.current = 'auth'
            return
        elif skey == 'imp':
            self.btn.disabled = False
            self.pop.content.text = 'Account Already Logged In'
            time.sleep(2)
            self.pop.dismiss()
            f = open('UserData.txt', 'wb')
            f.write(b'')
            f.close()
            return
        else:
            self.btn.disabled = False
            self.pop.content.text = 'Wrong login'
            time.sleep(2)
            self.pop.dismiss()
            return


class MainWindow(Screen):
    tb = ObjectProperty(None) #  text browser
    mtb = ObjectProperty(None) #  main text browser (for writing)
    gx = ObjectProperty(None) # gridlayout of files
    up = ObjectProperty(None) # upload file button
    vo = ObjectProperty(None) # join voice button
    fl = ObjectProperty(None) # float layout of screen
    pop = Popup(title='Status',auto_dismiss= False,
                  content=Label(text='Adding friend...'),
                  size_hint=(None, None), size=(250, 100))

    def getfile(self, b): # a function to pick a directory to store the picked file
        try:
            Tk().withdraw() #  dismiss the main screen
            pathname = filedialog.asksaveasfilename(initialfile=b.text) #  get save path
            if pathname == '':
                return
            query = encrypt_message(f'Ω¥•¼<>', skey)
            client.send(encrypt_message(str(len(query)), skey))
            client.send(query)
            time.sleep(0.001)
            query = encrypt_message('▓quitf', skey)
            client.send(encrypt_message(str(len(query)), skey))
            client.send(query)
            f_t = threading.Thread(target=self.getfile_main, args=(b, pathname))
            f_t.start()
        except:
            error_t()

    def getfile_main(self, b, d): # a function called to a thread to get/download a picked file to the server
        try:
            file = open(str(d), 'ab')
            self.pop.content.text = "Getting file..."
            self.pop.open()
            query = encrypt_message(f'◙°±©—₧ƒ<>{b.text}<>{user.nick}', skey)
            client.send(encrypt_message(str(len(query)), skey))
            client.send(query)
            time.sleep(1)
            data = ''
            while True:
                buff = decrypt_message(client.recv(100), skey)
                if buff == '-1' or data == b'-1':
                    break
                data = decrypt_file(client.recv(int(buff)), skey)
                file.write(data)
            self.pop.content.text = "File Received"
            file.close()
            time.sleep(2)
            self.pop.dismiss()
            self.load()
            query = encrypt_message(f'Ω¥•¼<>{target}', skey)
            client.send(encrypt_message(str(len(query)), skey))
            client.send(query)
            self.receive()
            return
        except Exception as e:
            print(e)
            self.pop.content.text = 'An error occurd please try again or re enter the room'
            self.pop.open()
            time.sleep(2)
            self.pop.dismiss()
            self.load()
            query = encrypt_message(f'Ω¥•¼<>{target}', skey)
            client.send(encrypt_message(str(len(query)), skey))
            client.send(query)
            self.receive()
            return
    
    def send_voice(self): # a function to send voice recordings
        global stream_rec
        while True:
            try:
                special.send(encrypt_file(stream_rec.read(1024), skey))
            except:
                self.vo.disabled = False
                self.pop.open()
                self.pop.content.text = "Disconnected from voice"
                time.sleep(2)
                self.pop.dismiss()
                return

    def leave_voice(self, b): # leave the voice chat
        global special
        special.close()
        special = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.vo.disabled = False
        self.fl.remove_widget(b)

    def voice_main(self): # main voice function
        global target, stream
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
            query = encrypt_message('▓<>' + target + '<>' + f'{user.nick} Joined The Voice Channel!', skey)
            client.send(encrypt_message(str(len(query)), skey))
            client.send(query)
            time.sleep(0.1)
            self.fl.add_widget(Button(text='Leave Voice', pos_hint={"x":0.88, "y": 0.24}, size_hint=(0.1, 0.05), on_release=self.leave_voice))
            mv_t = threading.Thread(target=self.send_voice)
            mv_t.start()
            while True:
                data = decrypt_file(special.recv(2828), skey)
                stream.write(data)
        except:
            self.vo.disabled = False
            self.pop.open()
            self.pop.content.text = "Disconnected from voice"
            time.sleep(2)
            self.pop.dismiss()
        return

    def voice(self): # starting voice communication thread
        self.vo.disabled = True
        v_t = threading.Thread(target=self.voice_main)
        v_t.start()
        

    def load(self): # a function to load files
        try:
            global target
            self.gx.bind(minimum_height=self.gx.setter('height')) #  adapt layout size
            query = encrypt_message(f'₧ƒ<>{user.nick}<>{target}', skey)
            client.send(encrypt_message(str(len(query)), skey))
            client.send(query)
            length = decrypt_message(client.recv(100), skey)
            filelist = decrypt_message(client.recv(int(length)), skey).split('<>') #  get filelist from server and sort it
            check = False #  set a variable for checking duplicates
            self.gx.clear_widgets()
            self.gx.add_widget(Label(text='File Repo:'))
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
        except:
            error_t()

    def write(self): # a function that writes to the server a message to send to the target
        self.mtb.focus = True
        if not str(self.mtb.text).isspace() and str(self.mtb.text) != '' and len(str(self.mtb.text)) < 1000 :
            message = f'{user.nick}: {self.mtb.text}'
            t = self.tb.text
            self.tb.text = str(t) + str(message) + '\r\n'
            self.mtb.text = ''
            try:
                global target
                query = encrypt_message('▓<>' + target + '<>' + message, skey)
                client.send(encrypt_message(str(len(query)), skey))
                client.send(query)
            except:
                t = self.tb.text
                self.tb.text =  str(t) + f'couldn\'t send message please try again or restart the app\r\n'
        elif len(str(self.mtb.text)) < 1000:
            t = self.tb.text
            self.tb.text = t + '\r\nCant be empty or longer than 999 chars'

    def send_file(self, f, t): # a functions called to a thread to upload a file to the server
        try:
            if f != '':
                p = str(f.split('/')[-1])
                file = open(str(f), 'rb')
                query = encrypt_message(f'ƒ₧—©±°◙<>{p}<>{t}', skey)
                length = encrypt_message(str(len(query)), skey)
                client.send(length)
                client.send(query)
                time.sleep(0.5)
                while True:
                    data = file.read(32768)
                    if data == b'':
                        file.close()
                        client.send(encrypt_message('-1', skey))
                        break
                    query = encrypt_file(data, skey)
                    client.send(encrypt_message(str(len(query)), skey))
                    client.send(query)
                    time.sleep(0.001)
                buff = decrypt_message(client.recv(100), skey)
                ans = decrypt_message(client.recv(int(buff)), skey)
                if ans == 'uploaded successfully©◙ƒ<>':
                        self.pop.content.text = 'Uploaded file'
                        self.pop.open()
                        time.sleep(2)
                        self.pop.dismiss()
                        self.load()
                        query = encrypt_message(f'Ω¥•¼<>{target}', skey)
                        client.send(encrypt_message(str(len(query)), skey))
                        client.send(query)
                        self.receive()
                        return
                else:
                    raise Exception()
            else:
                raise Exception()

        except Exception as e:
            print(e)
            self.pop.content.text = 'Uploading file failed'
            self.pop.open()
            time.sleep(2)
            self.pop.dismiss()
            self.load()
            query = encrypt_message(f'Ω¥•¼<>{target}', skey)
            client.send(encrypt_message(str(len(query)), skey))
            client.send(query)
            self.receive()
            return

    def sendFile(self): # a function to pick a file and start a thread to upload it
        try:
            Tk().withdraw() #  dismiss the main screen
            filename = filedialog.askopenfilename() #  get picked file path
            if filename != '':
                if int(os.path.getsize(filename)) < 100000000: #  limit file size to 10 MB
                    query = encrypt_message(f'Ω¥•¼<>', skey)
                    client.send(encrypt_message(str(len(query)), skey))
                    client.send(query)
                    query = encrypt_message('▓quitf', skey)
                    client.send(encrypt_message(str(len(query)), skey))
                    client.send(query)
                    self.pop.content.text = "Uploading file..."
                    self.pop.open()
                    file_thread = threading.Thread(target=self.send_file, args=(filename, target))
                    file_thread.start()
                else:
                    largeFile()
            else:
                return
        except:
            error_t()

    def receive_main(self): #  a function called to a thread to recieve message while in chat
        global special
        tries = 0
        while True:
            try:
                buff = decrypt_message(client.recv(100), skey)
                message = decrypt_message(client.recv(int(buff)), skey)
                k = message.split('<>')
                if k[0] == 'byebye±°':
                    special.close()
                    special = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sm.current = "friends"
                    sm.current_screen.load()
                    return

                if k[0] == 'filing±°':
                    return

                else:
                    t = self.tb.text
                    self.tb.text = t + k[0] + '\r\n'

            except:
                tries += 1
                if tries == 3:
                    self.pop.content.text = 'An error occurred please wait or restart the app'
                    self.pop.open()
                    time.sleep(2)
                    self.pop.dismiss()
                    sm.current = "friends"
                    sm.current_screen.load()
                    return
                else:
                    continue

    def receive(self): # start receiving thread
        if target == 'public':
            self.vo.disabled = True
            self.up.disabled = True
        else:
            self.vo.disabled = False
            self.up.disabled = False

        r_t = threading.Thread(target=self.receive_main)
        r_t.start()

    def leave(self): # leave room thread(leave room button)
        l_t = threading.Thread(target=self.leave_main)
        l_t.start()

    def leave_main(self): # leave room function
        try:
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
        except:
            error_t()
        


class FriendsScreen(Screen):
    bx = ObjectProperty(None)
    rq = ObjectProperty(None)
    pop = Popup(title='Status',auto_dismiss= False, # create a popup
                  content=Label(text='Error'),
                  size_hint=(None, None), size=(250, 100))

    def add_friend_screen(self): # go to add a friend screen
        sm.current = "addfriend"

    def public(self): # join public room
        try:
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
        except:
            error_t()

    def load(self): # load list of friends
        try:
            self.bx.bind(minimum_height=self.bx.setter('height')) #  adapt layout size
            query = encrypt_message(f'ø∞ö<>{user.email.decode()}', skey)
            client.send(encrypt_message(str(len(query)), skey))
            client.send(query)
            length = decrypt_message(client.recv(100), skey)
            friendlist = sorted(decrypt_message(client.recv(int(length)), skey).split('-'), key=str.lower) #  get friendlist string from server make it a list and sort it
            check = False #  set a variable for checking duplicates
            for ob in self.bx.children:
                if '(offline)' in ob.text or '(online)' in ob.text:
                    self.bx.remove_widget(ob)
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
        except:
            error_t()


    def start_private(self, button): # start private communications
        try:
            global target
            target = button.text.split('(')[0]
            query = encrypt_message(f'Ω¥•¼<>{target}', skey)
            client.send(encrypt_message(str(len(query)), skey))
            client.send(query)
            sm.current = "main"
            sm.current_screen.load()
            sm.current_screen.receive()
        except:
            error_t()

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
        try:
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
                time.sleep(2)
                self.pop.dismiss()
                sm.current = "friends"
                sm.current_screen.load()
            else:
                self.pop.content.text = 'No such user found'
                self.pop.open()
                time.sleep(2)
                self.pop.dismiss()
            return
        except:
            error_t()
    
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
        try:
            self.bx.bind(minimum_height=self.bx.setter('height')) #  adapt layout size
            query = encrypt_message(f'ø∞ö<>{user.email.decode()}', skey) #  send the required signal to the server
            client.send(encrypt_message(str(len(query)), skey)) #  send the length of the request to the server
            client.send(query) #  send the request to the server
            length = decrypt_message(client.recv(100), skey) #  get len of answer from server
            for ob in self.bx.children:
                if "Click on a friend to remove:" not in ob.text and "Go Back:" not in ob.text:
                    self.bx.remove_widget(ob)
            friendlist = decrypt_message(client.recv(int(length)), skey).split('-') #  get friendlist from server and sort it
            check = False #  set a variable for checking duplicates
            if friendlist != ['']: #  check if friendlist is not empty
                for friend in friendlist: #  go over recived friendlist
                    for obj in self.bx.children: #  go over the existing widgets in layout
                        if friend.split('(')[0] == obj.text.split('(')[0]: #  check if button already exiest for friend
                            check = True # if found duplicate let the program know 
                            break #  end the inside loop for better runtime
                    if friend.split('(')[0] != '' and not check: #  if friend is not nothing and his duplicate not found
                        self.bx.add_widget(Button(text=friend, on_release=self.remove_f)) #  add button to friend
                    check = False #  reset the duplicate checking variable
        except:
            error_t()

    def remove_f(self, b): #  is getting the screen and button
        rf = threading.Thread(target=self.remove_f_main, args=(b,))
        rf.start()
    
    def remove_f_main(self, b): # main removing friend function
        try:
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
                self.bx.remove_widget(b)
                time.sleep(2)
                self.pop.dismiss()
                sm.current = "friends"
                sm.current_screen.load()
            else:
                self.pop.content.text = 'An error occurred'
                self.pop.open()

                time.sleep(2)
                self.pop.dismiss()
                sm.current = "friends"
                sm.current_screen.load()
            return
        except:
            error_t()

class Requests(Screen):
    bx = ObjectProperty(None)
    pop = Popup(title='Status',auto_dismiss= False, # create a popup
                  content=Label(text='Friend'),
                  size_hint=(None, None), size=(250, 100))
    
    def back(self): # go back to friend screen
        sm.current = "friends"
        sm.current_screen.load()

    def load(self): # a method for loading the friend requests
        try:
            self.bx.bind(minimum_height=self.bx.setter('height')) #  adapt layout size
            query = encrypt_message(f'₧—é<>{user.nick}<>', skey) #  send the required signal to the server
            client.send(encrypt_message(str(len(query)), skey)) #  send the length of the request to the server
            client.send(query) #  send the request to the server
            length = decrypt_message(client.recv(100), skey) #  get len of answer from server
            requests = decrypt_message(client.recv(int(length)), skey).split('-') #  get friendlist from server and sort it
            check = False #  set a variable for checking duplicates
            for ob in self.bx.children:
                if "Go Back:" not in ob.text and "Select a friend you want to add/reject:" not in ob.text :
                    self.bx.remove_widget(ob)
                    continue
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
        except:
            error_t()

    def accept_reject(self, b): # accept\reject thread
        ar = threading.Thread(target=self.accept_reject_main, args=(b,))
        ar.start()

    def accept_reject_main(self, b): # main function to accept\reject friend request
        try:
            ans = b.text.split(' ')
            if ans[0] == 'accept':
                query = encrypt_message(f'éè╣<>accept<>{user.nick}<>{ans[1]}', skey) #  send the required signal to the server
                client.send(encrypt_message(str(len(query)), skey)) #  send the length of the request to the server
                client.send(query) #  send the request to the server
                sm.current = 'friends'
                sm.current_screen.load()

            elif ans[0] == 'reject':
                query = encrypt_message(f'éè╣<>reject<>{user.nick}<>{ans[1]}', skey) #  send the required signal to the server
                client.send(encrypt_message(str(len(query)), skey)) #  send the length of the request to the server
                client.send(query) #  send the request to the server
                sm.current == 'friends'
                sm.current_screen.load()
            return
        except:
            error_t()

class AuthScreen(Screen):
    inpu = ObjectProperty(None)
    gb = ObjectProperty(None)
    bt = ObjectProperty(None)
    pop = Popup(title='Status', auto_dismiss = False, # create a popup
        content=Label(text='Authinticating...'),
        size_hint=(None, None), size=(250, 100))

    def auth(self):
        auth_t = threading.Thread(target=self.auth_main)
        auth_t.start()

    def auth_main(self):
        try:
            global client, skey
            self.bt.disabled = True
            self.gb.disabled = True
            self.pop.open()
            client.send(encrypt_message(str(self.inpu.text), skey))
            ans = decrypt_message(client.recv(100), skey)
            if ans == 'auth' + user.nick[:5]:
                client.send(encrypt_message('im ready', skey))
                self.bt.disabled = False
                self.gb.disabled = False
                self.pop.dismiss()
                sm.current = 'friends'
                sm.current_screen.load()
                return
            else:
                client.send(encrypt_message('im falid', skey))
                self.pop.content.text = 'Auth Failed'
                time.sleep(2)
                self.pop.dismiss()
                self.bt.disabled = False
                self.gb.disabled = False
                sm.current = 'login'
                return
        except:
            sm.current = 'login'
            return

    def goback(self):
        client.send(encrypt_message('000000', skey))
        sm.current = 'login'
        return


class WindowManager(ScreenManager):
    pass


#  start of pre-load operation
kv = Builder.load_file("SSS.kv")
sm = WindowManager()

screens = [LoginWindow(name="login"), AuthScreen(name="auth"), Requests(name="requests") ,AddFriend(name="addfriend"), CreateAccountWindow(name="create"),MainWindow(name="main"), FriendsScreen(name="friends"), RemoveFriend(name="remove")]
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
        query = encrypt_message(f'Ω¥•¼<>', skey)
        client.send(encrypt_message(str(len(query)), skey))
        client.send(query)
        if target == 'public':
            query = encrypt_message('t◙<>quit_pub', skey)
            client.send(encrypt_message(str(len(query)), skey))
            client.send(query)
        query = encrypt_message('▓quit<>' + target + '<>' + f'{user.nick} left the room', skey)
        client.send(encrypt_message(str(len(query)), skey))
        client.send(query)
        exit()
    except:
        pass
