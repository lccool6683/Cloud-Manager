import tkMessageBox
import tkSimpleDialog
from Dialog import Dialog


import inquirer

from mongo import *
from googleLogic import *
from googleLogic import main as google_main
#from raspcloud import *
from dropboxLogic import dropbx_get_token as dp_get_token
#from raspcloud import main as google_main




def account_selection(userID):
    account_dict = get_account(userID)
    choices = {}
    for account, values in account_dict.items():
        choices.update({account : values['type']})

    #account_name = raw_input("Which drive do you want to connect?")

    questions = [
        inquirer.List('drive',
                      message="Which drive do you want to connect?",
                      choices= choices,
                      ),
    ]
    account_name = inquirer.prompt(questions)
    #print account_name
    return account_dict, account_name['drive'], choices[account_name['drive']]
def menu():
    questions = [
        inquirer.List('action',
                      choices= ['Connect to drive', 'oauth']
                      ),
    ]
    acution = inquirer.prompt(questions)
    return acution['action']


class OldDialogDemo(Frame):
    global account_dict, account_list
    def __init__(self, userID, master=None):
        global account_dict, account_list
        Frame.__init__(self, master)
        Pack.config(self)  # same as self.pack()
        self.userID = userID
        ans = Dialog(self,
                     title='OAuth!',
                     text='Which cloud storage do you want to connect".',
                     bitmap='',
                     default=0, strings=('Dropbox', 'Google'))
        if ans.num == 0: self.dropbox()
        if ans.num == 1: self.google(userID)

        account_list.delete(0, END)
        account_dict = get_account(userID)
        for account, values in account_dict.items():
            account_list.insert(END, account)
        account_list.update_idletasks()

    def dropbox(self):
        dropbx_get_token(userID, True)
    def google(self, userID):
        get_token(userID, True)


def oauth(userID):
    OldDialogDemo(userID)
    print 'hello'


def CheckLogin():
    global rootA
    global frame
    global account_sel_window
    global userID
    global account_list, account_dict, userID
    username = nameEL.get()
    password = pwordEL.get()
    #username = 'testuser'
    #password = 'password'
    (success, userID) = login(username, password)
    if success:  # Checks to see if you entered the correct data.
        frame.destroy()
        rootA.destroy()

        account_sel_window = Tk()  # Opens new window
        account_sel_window.title('select account')
        account_sel_window.geometry()  # Makes the window a certain size

        account_dict = get_account(userID)
        account_list = Listbox(account_sel_window)
        account_list.pack()
        for account, values in account_dict.items():
            account_list.insert(END, account)
        print account_list
        dir_load_bt = Button(account_sel_window, text="OK", command=lambda: dir_load(account_list, account_dict, userID)).pack()
        oauth_bt = Button(account_sel_window, text="Add Drive",command=lambda: oauth(userID)).pack()
        del_bt = Button(account_sel_window, text="Delete Drive", command=lambda: delkey(userID, account_list)).pack()
        rlbl.pack()  # Pack is like .grid(), just different
        account_sel_window.mainloop()
    else:
        r = Tk()
        r.title('Error')
        r.geometry('150x50')
        rlbl = Label(r, text='\n[!] Invalid Login')
        rlbl.pack()
        r.mainloop()

def dir_load(account_list, account_dict, userID, gui = None):
    global account_sel_window, account_type, switch_account_sel_window, dir_listbox

    account_index = account_list.curselection()
    account_name = account_list.get(account_index)
    #print account_name
    #print account_dict, account_name, account_dict[account_name]['type']

    account_type = account_dict[account_name]['type']


    if account_type == 'google':
        global pydrive, current_dir, dir_list
        try:
            pydrive = pycloud(account_dict, account_name, userID)
        except:
            r = Tk()
            r.title('Error')
            r.geometry('150x50')
            rlbl = Label(r, text='\nUnauthorized device')
            rlbl.pack()
            r.mainloop()
            return
        current_dir = "root"
        dir_list = ''
        dir_list = pydrive.print_dir(current_dir, dir_list)

    if account_type == 'dropbox':
        global current_dir, acc_dp
        try:
            acc_dp = start_raspberry_cloud('s', account_dict[account_name]['token'], userID, True)
        except:
            r = Tk()
            r.title('Error')
            r.geometry('150x50')
            rlbl = Label(r, text='\nUnauthorized device')
            rlbl.pack()
            r.mainloop()
            return
        current_dir = "/"

    if gui == None:
        dir_window = Tk()
        dir_window.title('file list')

    if gui == None:
        button_frame = Frame(dir_window)
        upload_bt = Button(button_frame, text="upload",command=lambda: upload(dir_listbox))
        upload_bt.grid(column = 0, row = 0)
        download_bt = Button(button_frame, text="download",command=lambda: download(dir_listbox))
        download_bt.grid(column=1, row=0)
        mkdir_bt = Button(button_frame, text="new folder",command=lambda: mkdir(dir_listbox))
        mkdir_bt.grid(column=4, row=0)
        merge_bt = Button(button_frame, text="merge",command=merge)
        merge_bt.grid(column=5, row=0)
        switch_bt = Button(button_frame, text="switch",command=switch)
        switch_bt.grid(column=6, row=0)
        switch_bt = Button(button_frame, text="delete", command=lambda: delete(dir_listbox))
        switch_bt.grid(column=3, row=0)
        switch_bt = Button(button_frame, text="rename", command=lambda: rename(dir_listbox))
        switch_bt.grid(column=2, row=0)
        button_frame.grid(column=0, row=0)

    if gui == None:
        dir_listbox = Listbox(dir_window, selectmode='multiple', width=50)
        dir_listbox.grid(column=0, row=1)
    if gui:
        dir_listbox.delete(0, END)
    ls(dir_listbox)
    if gui:
        switch_account_sel_window.destroy()
    if gui == None:
        account_sel_window.destroy()
    dir_listbox.bind('<Double-1>', lambda x: change_dir(dir_listbox))
    if gui == None:
        dir_window.mainloop()

def change_dir(dir_listbox):
    global account_type
    if account_type == 'google':
        global pydrive, dir_list, current_dir
        print 'cd'
        print dir_listbox.selection_get()[1:len(dir_listbox.selection_get())]
        if dir_listbox.selection_get() == '..':
            current_dir = pydrive.return_id_by_name(dir_listbox.selection_get(),dir_list)
        else:
            current_dir = pydrive.return_id_by_name(dir_listbox.selection_get()[1:len(dir_listbox.selection_get())], dir_list)
        dir_list = pydrive.print_dir(current_dir, dir_list)
        dir_listbox.delete(0, END)
        ls(dir_listbox)
    if account_type == 'dropbox':
        global current_dir
        handle_input  = dir_listbox.selection_get().strip()
        '''
        if current_dir == "/":
            current_dir = current_dir + handle_input
        # otherwise tack the newly entered directory onto the previous one so that we can get into nested folders
        else:
            current_dir = current_dir + "/" + handle_input
        '''
        if handle_input == '.':
            current_dir = current_dir + "/.."
        else:
            current_dir = handle_input
        dir_listbox.delete(0, END)
        ls(dir_listbox)

def ls(dir_listbox):
    global account_type
    if account_type == 'google':
        global pydrive, current_dir, dir_list
        dir_listbox.insert(END, '..')
        for file_list in dir_list:
            for file1 in file_list:
                dir_listbox.insert(END, '/%s' % file1['title'])
        dir_list = pydrive.print_dir(current_dir, dir_list)
    if account_type == 'dropbox':
        global acc_dp
        folder_metadata = acc_dp.client.metadata(current_dir)
        dir_listbox.insert(END, '.')
        for key, value in folder_metadata.iteritems():
            if type(value) is list:
                for listitem in value:
                    if type(listitem) is dict:
                        # print listitem
                        for nested_key, nested_value in listitem.iteritems():
                            if nested_key == 'path':
                                dir_listbox.insert(END, nested_value)
                                #print JColor.FGORANGE + nested_value + JColor.ENDC

def delete(dir_listbox):
    items = dir_listbox.curselection()
    if account_type == 'google':
        global dir_list, pydrive
        file_name =dir_listbox.get(items)
        fileID = pydrive.return_id_by_name(file_name[1:len(file_name)], dir_list)
        file = pydrive.drive.CreateFile({'id': fileID})
        file.Delete()
        dir_listbox.delete(0, END)
        dir_list = pydrive.print_dir(current_dir, dir_list)
    if account_type == 'dropbox':
        global acc_dp
        file_name = dir_listbox.get(items)
        acc_dp.client.file_delete(file_name)
        dir_listbox.delete(0, END)
    ls(dir_listbox)

def upload(dir_listbox):
    global account_type
    file_tk = Tk()
    filez = tkFileDialog.askopenfilenames(parent=file_tk, title='Choose a file')
    if account_type == 'dropbox':
        global acc_dp, current_dir
        result = tkMessageBox.askquestion("Encrypt?", "encrypt files")
        for file in file_tk.tk.splitlist(filez):
            if result == 'yes':
                acc_dp.new_upload(current_dir, file, os.path.basename(file), 'true', acc_dp.client)
            else:
                acc_dp.new_upload(current_dir, file, os.path.basename(file), 'false', acc_dp.client)
        file_tk.withdraw()
    if account_type == 'google':
        global pydrive, current_dir, dir_list
        result = tkMessageBox.askquestion("Encrypt?", "encrypt files")
        for file in file_tk.tk.splitlist(filez):
            if result == 'yes':
                pydrive.encrypt(file, os.path.basename(file) + '.enc', str(get_mac()))
                dir_tree = pydrive.drive.ListFile({'q': 'trashed=false', 'maxResults': 1000})
                metadata = pydrive.upload(current_dir,  'data_buffer/'+os.path.basename(file) + '.enc')
            else:
                success = False
                while (success == False):
                    dir_tree = pydrive.drive.ListFile({'q': 'trashed=false', 'maxResults': 1000})
                    metadata = pydrive.upload(current_dir, file)
                    checksum = metadata['md5Checksum']
                    print checksum
                    print pydrive.get_checksum(file)
                    if pydrive.get_checksum(file) == checksum:
                        success = True
        file_tk.withdraw()
    dir_listbox.delete(0, END)
    ls(dir_listbox)

def download(dir_listbox):
    global account_type
    dl_list = []
    items = dir_listbox.curselection()
    for i in items:
        # file_name = l.get(i).replace("'", "").replace("u", "")
        # dl_list.append(file_name)
        dl_list.append(dir_listbox.get(i))
    if account_type == 'google':
        global dir_list, pydrive

        for file in dl_list:
            print file[1:len(file)]
            success = False
            while (success == False):
                dir_tree = pydrive.drive.ListFile({'q': 'trashed=false', 'maxResults': 1000})
                metadata = pydrive.download(file[1:len(file)], dir_tree)
                checksum = metadata['md5Checksum']
                print checksum
                print pydrive.get_checksum('download/' + file[1:len(file)])
                if pydrive.get_checksum('download/' + file[1:len(file)]) == checksum:
                    success = True
    if account_type == 'dropbox':
        global acc_dp, current_dir
        for file in dl_list:
            acc_dp.download_file(current_dir, file[1:len(file)], acc_dp.client)

def rename(dir_listbox):
    global account_type
    root = Tkinter.Tk()
    root.withdraw()
    items = dir_listbox.curselection()
    file = dir_listbox.get(items)
    newname = tkSimpleDialog.askstring('Name', 'File Name?')
    root.destroy()
    if account_type == 'google':
        global pydrive, dir_list, current_dir
        file_name = dir_listbox.get(items)
        print 'hello'
        print file_name
        fileID = pydrive.return_id_by_name(file_name[1:len(file_name)], dir_list)
        print fileID
        file1 = pydrive.drive.CreateFile({'id': fileID})
        file1.FetchMetadata(fetch_all=True)
        file1['title'] = newname
        file1.Upload()


        dir_listbox.delete(0, END)
        dir_list = pydrive.print_dir(current_dir, dir_list)
    if account_type == 'dropbox':
        global acc_dp
        acc_dp.client.file_move(file, file.replace(os.path.basename(file), '') + newname)
        #acc_dp.client.file_create_folder(foldername)
        dir_listbox.delete(0, END)
    ls(dir_listbox)


def mkdir(dir_listbox):
    global account_type
    root = Tkinter.Tk()
    root.withdraw()
    foldername = tkSimpleDialog.askstring('Folder', 'Folder Name?')
    root.destroy()
    if account_type == 'google':
        global pydrive, dir_list, current_dir
        pydrive.creat_folder(current_dir, foldername)
    if account_type == 'dropbox':
        global acc_dp
        acc_dp.client.file_create_folder(foldername)
    dir_listbox.delete(0, END)
    ls(dir_listbox)

def merge():
    global account_type
    if account_type == 'google':
        global pydrive
        pydrive.merge(pydrive.userID, True)
    if account_type == 'dropbox':
        global acc_dp
        acc_dp.merge(True)

def switch():
    global account_list, account_dict, userID, switch_account_sel_window
    switch_account_sel_window = Tk()  # Opens new window
    switch_account_sel_window.title('select account')
    switch_account_sel_window.geometry()  # Makes the window a certain size

    account_dict = get_account(userID)
    account_list = Listbox(switch_account_sel_window)
    account_list.pack()
    for account, values in account_dict.items():
        account_list.insert(END, account)
    print account_list
    dir_load_bt = Button(switch_account_sel_window, text="OK",
                         command=lambda: dir_load(account_list, account_dict, userID, True)).pack()

    rlbl = Label(switch_account_sel_window, text='\n[+] Logged In')  # "logged in" label
    rlbl.pack()  # Pack is like .grid(), just different
    switch_account_sel_window.mainloop()

def main():
    clearscreen()
    if  len(sys.argv) == 2:
        if sys.argv[1] == '-c':
            while (1):
                print 'Enter new to create new user'
                username = raw_input("username: ")
                if username == 'new':
                    clearscreen()
                    new_username = raw_input("username: ")
                    new_password = raw_input("password: ")
                    success = addUser(new_username, new_password)
                    continue
                password = raw_input("password: ")
                # username = 'testuser'
                # password = 'test'




                (success, userID) = login(username, password)
                if success:
                    print 'success login'
                    print userID
                else:
                    print 'bye'
                    sys.exit()
                while (1):
                    action = menu()
                    if action == 'oauth':
                        questions = [
                            inquirer.List('drive type',
                                          message="Which cloud storage do you want to connect?",
                                          choices=['Google', 'Dropbox']
                                          ),
                        ]
                        cloud_type = inquirer.prompt(questions)['drive type']
                        if cloud_type == 'Google':
                            get_token(userID)
                        elif cloud_type == 'Dropbox':
                            dp_get_token(userID)
                    elif action == 'Connect to drive':
                        account_dict, account_name, account_type = account_selection(userID)
                        if account_type == 'google':
                            google_main(account_dict, account_name, userID)
                        if account_type == 'dropbox':
                            start_raspberry_cloud('s', decrypt_string(account_dict[account_name]['token']), userID)
    elif len(sys.argv) == 1:
        global nameEL
        global pwordEL  # More globals :D
        global rootA
        global frame

        rootA = Tk()  # This now makes a new window.
        frame = Frame(rootA)
        frame.grid()
        rootA.title('Login')  # This makes the window title 'login'

        intruction = Label(frame, text='Please Login\n')  # More labels to tell us what they do
        intruction.grid(sticky=E)  # Blahdy Blah

        nameL = Label(frame, text='Username: ')  # More labels
        pwordL = Label(frame, text='Password: ')  # ^
        nameL.grid(row=1, sticky=W)
        pwordL.grid(row=2, sticky=W)

        nameEL = Entry(frame)  # The entry input
        pwordEL = Entry(frame, show='*')
        nameEL.grid(row=1, column=1)
        pwordEL.grid(row=2, column=1)

        loginB = Button(frame, text='Login',
                        command=CheckLogin)  # This makes the login button, which will go to the CheckLogin def.
        loginB.grid(row=3, column=0, sticky=W)

        signupB = Button(frame, text='signup',
                         command=signup)  # This makes the login button, which will go to the CheckLogin def.
        signupB.grid(row=3, column=1, sticky=W)

        frame.mainloop()




def signup():
    username = nameEL.get()
    password = pwordEL.get()
    success = addUser(username, password)
    r = Tk()

    r.geometry('200x50')
    if success:
        r.title('Success:')
        rlbl = Label(r, text='\nAccount created successfully')

    else:
        r.title('Error:')
        rlbl = Label(r, text='\n[!] This username is taken')
    rlbl.pack()
    r.mainloop()

main()


