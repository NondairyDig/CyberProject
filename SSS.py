from tkinter.constants import FALSE
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


"""udp, files, message history,  notifications""" # to-do list
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # global variable for socket
logged_in = False  # global variable for checking if log in is approved
skey = b''  # global variable for session key
user = '' #  global variable for user
nickname = ''  # global variable for user nickname
file_key = b'K4a6Y7CA8JZMNTTv8-XeSbX8BT3ywLmtz177ry11d0o='  # key to decrypt data file
host = '127.0.0.1'  # server address
save = False  # global variable whether to save the file or not

def decrypt_message(encrypted_message, key): #  decrypt a message using Fernet module
    f = Fernet(key) #  initialize module in parameter
    decrypted_message = f.decrypt(encrypted_message) # decrypt the message
    return decrypted_message.decode() #  return the decrypted message as plain text


def encrypt_message(message, key):
    encoded_message = message.encode()
    f = Fernet(key)
    encrypted_message = f.encrypt(encoded_message)
    return encrypted_message


def encrypt_file(file, key):
    f = Fernet(key)
    encrypted_file = f.encrypt(file)
    return encrypted_file


def decrypt_file(encrypted_file, key):
    f = Fernet(key)
    decrypted_file = f.decrypt(encrypted_file)
    return decrypted_file


def invalidUsername():
    pop = Popup(title='Invalid Username',
                  content=Label(text='please enter username.'),
                  size_hint=(None, None), size=(400, 400))
    pop.open()

def invalidPassword():
    pop = Popup(title='Invalid Password',
                  content=Label(text='Password needs to be at least 7 charachters long.'),
                  size_hint=(None, None), size=(400, 400))

    pop.open()

def invalidEmail():
    pop = Popup(title='Invalid Email',
                  content=Label(text='Please Re-enter Email'),
                  size_hint=(None, None), size=(400, 400))
    pop.content.text = "bruh"
    pop.open()


class CreateAccountWindow(Screen):
    username = ObjectProperty(None)
    email = ObjectProperty(None)
    password = ObjectProperty(None)
    btn = ObjectProperty(None)
    pop = Popup(title='Status', auto_dismiss=False,
                  content=Label(text='Connecting...'),
                  size_hint=(None, None), size=(250, 100))

    def submit(self):
        s_username = self.username.text
        s_email = self.email.text
        s_password = self.password.text
        self.pop.open()
        if len(s_username) < 1:
            invalidUsername()
            self.email.text = ""
            self.password.text = ""
            self.username.text = ""
            return

        if len(s_email) < 8 or not re.search('^(\w|\.|\_|\-)+[@](\w|\_|\-|\.)+[.]\w{2,3}$', str(s_email)):
            invalidEmail()
            self.email.text = ""
            self.password.text = ""
            self.username.text = ""
            return

        if len(s_password) < 7:
            invalidPassword()
            self.email.text = ""
            self.password.text = ""
            self.username.text = ""
            return
        else:
            s_t = threading.Thread(target=self.signup, args=(s_email, s_password, s_username))
            s_t.start()
    
    def signup(self, e, p, n):
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
            if skey:
                friends = decrypt_message(client.recv(1024), skey)
                user.update_f_list(friends)
                self.btn.disabled = False
                self.pop.dismiss()
                client.send('im ready'.encode())
                sm.current = 'friends'
                sm.current_screen.load()
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
    
    def login(self):
        self.email.text = ""
        self.password.text = ""
        self.username.text = ""
        sm.current = "login"


class LoginWindow(Screen):
    email = ObjectProperty(None)
    password = ObjectProperty(None)
    cb = ObjectProperty(None)
    btn = ObjectProperty(None)
    pop = Popup(title='Status',auto_dismiss= False,
                  content=Label(text='Connecting...'),
                  size_hint=(None, None), size=(250, 100))

    def kook(self):
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

    def createBtn(self):
        self.email.text = ""
        self.password.text = ""
        sm.current = "create"
    
    def loginBtn(self):
        s_email = self.email.text
        s_password = self.password.text
        if len(s_email) < 8 or not re.search('^(\w|\.|\_|\-)+[@](\w|\_|\-|\.)+[.]\w{2,3}$', str(s_email)):
            invalidEmail()
            self.email.text = ""
            self.password.text = ""
            self.username.text = ""
            return
        
        if len(s_password) < 7:
            invalidPassword()
            self.email.text = ""
            self.password.text = ""
            self.username.text = ""
            return
        else:
            l_t = threading.Thread(target=self.login, args=(s_email, s_password,))
            l_t.start()
    
    def login(self, e, p):
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
        if skey:
            if self.cb.active:
                f = open('UserData.txt', 'wb')
                f.write(encrypt_message(str('YEs'.encode()) + '  ' + str(e) + '  ' + str(p), file_key))
                f.close()
            friends = decrypt_message(client.recv(1024), skey)
            user.update_f_list(friends)
            self.btn.disabled = False
            client.send('im ready'.encode())
            self.pop.dismiss()
            sm.current = 'friends'
            sm.current_screen.load()
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
    pop = Popup(title='Status',auto_dismiss= False,
                  content=Label(text='Adding friend...'),
                  size_hint=(None, None), size=(250, 100))

    def write(self):
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
            self.tb.text = t + '\r\nCant be empty or longer than 999'

    def limit(self):
        if len(str(self.mtb.text)) > 1000:
            t = self.mtb.text
            self.mtb.text = ''
            self.mtb.text = t

    def logOut(self): #  log-out function
        try:
            delete = open('UserData.txt', 'wb') #  open "cookie" file
            delete.write(b'') #  reset the file
        except:
            pass
        sm.current = "login" #  go to the main log-in page

    def send_file(self, f, t):
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
                    self.receive()
                    return
            else:
                self.pop.content.text = 'Uploading file failed'
                self.pop.open()
                time.sleep(1)
                self.pop.dismiss()
                self.receive()
                return
        else:
            return

    def sendFile(self):
        Tk().withdraw() #  dismiss the main screen
        filename = filedialog.askopenfilename() #  get picked file path
        if int(os.path.getsize(filename)) < 1000000:
            if filename != '':
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

    def receiv_main(self):
        while True:
            try:
                buff = decrypt_message(client.recv(100), skey)
                message = decrypt_message(client.recv(int(buff)), skey)
                k = message.split('<>')
                if k[0] == 'byebye±°':
                    sm.current = "friends"
                    return

                if k[0] == 'filing±°':
                    return

                else:
                    t = self.tb.text
                    self.tb.text = t + k[0]
            

            except Exception as e:
                print('An error occurred: ' + str(e))
                return

    def receive(self):
        r_t = threading.Thread(target=self.receiv_main)
        r_t.start()


    def leave(self):
        l_t = threading.Thread(target=self.leave_main)
        l_t.start()

    def leave(self):
        global target
        if target == 'public':
            query = encrypt_message('t◙<>quit_pub', skey)
            client.send(encrypt_message(str(len(query)), skey))
            client.send(query)
        query = encrypt_message('▓quit<>' + target + '<>' + f'{user.nick} left the room', skey)
        client.send(encrypt_message(str(len(query)), skey))
        client.send(query)
        return


class FriendsScreen(Screen):
    bx = ObjectProperty(None)
    def add_friend_screen(self):
        sm.current = "addfriend"

    def public(self):
        global target
        target = 'public'
        query = encrypt_message('t◙<>public', skey)
        client.send(encrypt_message(str(len(query)), skey))
        client.send(query)
        sm.current = "main"
        sm.current_screen.receive()

    def load(self):
        self.bx.bind(minimum_height=self.bx.setter('height')) #  adapt layout size
        query = encrypt_message(f'ø∞ö<>{user.email.decode()}', skey)
        client.send(encrypt_message(str(len(query)), skey))
        client.send(query)
        length = decrypt_message(client.recv(100), skey)
        friendlist = decrypt_message(client.recv(int(length)), skey).split('-') #  get friendlist from server and sort it
        check = False #  set a variable for checking duplicates
        if friendlist != ['']: #  check if friendlist is not empty
            for friend in friendlist: #  go over recived friendlist
                for obj in self.bx.children: #  go over the existing widgets in layout
                    if friend == obj.text: #  check if button already exiest for friend
                        check = True # if found duplicate let the program know 
                        break #  end the inside loop for better runtime
                if friend != '' and not check: #  if friend is not nothing and his duplicate not found
                    self.bx.add_widget(Button(text=friend, on_release=self.start_private)) #  add button to friend
                check = False #  reset the duplicate checking variable

    def start_private(self, button):
        global target
        target = button.text
        sm.current = "main"
        sm.current_screen.receive()

    def remove_friend(self):
        sm.current = "remove"
        sm.current_screen.load()



class AddFriend(Screen):
    friend = ObjectProperty(None)
    pop = Popup(title='Status',auto_dismiss= False,
                  content=Label(text='Adding friend...'),
                  size_hint=(None, None), size=(250, 100))

    def add_friend(self):
        global user
        self.pop.content.text = 'Adding Friend...'
        self.pop.open()
        query = encrypt_message(f'üΩ¥<>{user.email.decode()}<>{self.friend.text}' , skey)
        client.send(encrypt_message(str(len(query)), skey))
        client.send(query)
        length = decrypt_message(client.recv(100), skey)
        ans = decrypt_message(client.recv(int(length)), skey)
        if ans == 'added':
            self.pop.content.text = 'Added friend successfully'
            time.sleep(1)
            self.pop.dismiss()
            sm.current = "friends"
            sm.current_screen.load()
        else:
            self.pop.content.text = 'No such user found'
            self.pop.open()
            time.sleep(1)
            self.pop.dismiss()
    
    def goBack(self):
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
                if friend != '' and not check: #  if friend is not nothing and his duplicate not found
                    self.bx.add_widget(Button(text=friend, on_release=self.remove_f)) #  add button to friend
                check = False #  reset the duplicate checking variable

    def remove_f(self, b): #  is getting the screen and button
        global user #  get the global user variable
        self.pop.content.text = 'Removing friend...'
        self.pop.open()
        query = encrypt_message(f'™╣¶<>{user.email.decode()}<>{b.text}' , skey)
        client.send(encrypt_message(str(len(query)), skey))
        client.send(query)
        length = decrypt_message(client.recv(100), skey)
        ans = decrypt_message(client.recv(int(length)), skey)
        if ans == 'removed':
            self.pop.content.text = 'Removed friend successfully'
            self.pop.open()
            time.sleep(1)
            self.pop.dismiss()
            sm.current = "friends"
            sm.current_screen.load()
        else:
            self.pop.content.text = 'An error occurred'
            self.pop.open()
            time.sleep(1)
            self.pop.dismiss()
            sm.current = "friends"
            sm.current_screen.load()



class WindowManager(ScreenManager):
    pass


#  start of pre-load operation
kv = Builder.load_file("SSS.kv")

sm = WindowManager()

screens = [AddFriend(name="addfriend"), LoginWindow(name="login"), CreateAccountWindow(name="create"),MainWindow(name="main"), FriendsScreen(name="friends"), RemoveFriend(name="remove")]
for screen in screens:
    sm.add_widget(screen)

sm.size_hint_min = 0.5, 0.5
sm.current = "login" #  start from log-in window
sm.current_screen.kook() #  check for automatic log-in with the kook() function

class SSS(App):
    def build(self):
        return sm #  return the screen manager, type: WindowManager


if __name__ == "__main__":
    SSS().run() #  run GUI
