import Tkinter
import hashlib
import tkFileDialog

import shutil
import tkSimpleDialog

from Crypto.Cipher import AES
from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive
from oauth2client.client import OAuth2Credentials
import JColor
from hashlib import md5
from Crypto import Random
from mongo import *
import inquirer
from Tkinter import *
import dropbox
import os
from copy import deepcopy
from uuid import getnode as get_mac
from dropboxLogic import *
import base64

'''
gauth = GoogleAuth()
gauth.credentials= OAuth2Credentials.from_json('{"_module": "oauth2client.client", "scopes": ["https://www.googleapis.com/auth/drive.install", "https://www.googleapis.com/auth/drive.file"], "token_expiry": "2017-04-28T09:18:38Z", "id_token": null, "access_token": "ya29.Gls6BGdrARiB18KGgg-tI7GSTcXTagk3qKIjAVKQ4b9UWJxHI8y99uycDZ2kuenTiPf-EIEEvXS2-3b_JaApiS3MetciI5gmOBGjsAZwprwcdaiotuqep_BnThyW", "token_uri": "https://accounts.google.com/o/oauth2/token", "invalid": false, "token_response": {"access_token": "ya29.Gls6BGdrARiB18KGgg-tI7GSTcXTagk3qKIjAVKQ4b9UWJxHI8y99uycDZ2kuenTiPf-EIEEvXS2-3b_JaApiS3MetciI5gmOBGjsAZwprwcdaiotuqep_BnThyW", "token_type": "Bearer", "expires_in": 3600, "refresh_token": "1/lBJ-mUST-qhtVSy4asMPqrMRzMn1N3KLHxapInZlYbxIwmUWZczRxiwLwoMNX2Oo"}, "client_id": "752408724558-646evescmmstmhncj4vqo5jhk94esb4e.apps.googleusercontent.com", "token_info_uri": "https://www.googleapis.com/oauth2/v3/tokeninfo", "client_secret": "Vt-GWFmR088SlNCOtaEtztNl", "revoke_uri": "https://accounts.google.com/o/oauth2/revoke", "_class": "OAuth2Credentials", "refresh_token": "1/lBJ-mUST-qhtVSy4asMPqrMRzMn1N3KLHxapInZlYbxIwmUWZczRxiwLwoMNX2Oo", "user_agent": null}')
drive = GoogleDrive(gauth)
gauth2 = GoogleAuth()
gauth2.credentials= OAuth2Credentials.from_json('{"_module": "oauth2client.client", "scopes": ["https://www.googleapis.com/auth/drive.install", "https://www.googleapis.com/auth/drive.file"], "token_expiry": "2017-04-28T23:31:28Z", "id_token": null, "access_token": "ya29.Gls6BA-Z7kq-TmlgQiGHnZOVl0epXg0pfN4pZi96oOe4Ktk-tDZEGKeO7c5mayqgUti07i2JXJ-MCqYKOUUfUYwLsjYKtPSlLA7-ma05pQOlwmcBPoFtCtGks8fz", "token_uri": "https://accounts.google.com/o/oauth2/token", "invalid": false, "token_response": {"access_token": "ya29.Gls6BA-Z7kq-TmlgQiGHnZOVl0epXg0pfN4pZi96oOe4Ktk-tDZEGKeO7c5mayqgUti07i2JXJ-MCqYKOUUfUYwLsjYKtPSlLA7-ma05pQOlwmcBPoFtCtGks8fz", "token_type": "Bearer", "expires_in": 3600, "refresh_token": "1/b59IfWyeEYvYtPyJv3NMazOV78Tofa6qEvhifJSFu7mhobZ1Ve6FazoB6stxXQ76"}, "client_id": "752408724558-646evescmmstmhncj4vqo5jhk94esb4e.apps.googleusercontent.com", "token_info_uri": "https://www.googleapis.com/oauth2/v3/tokeninfo", "client_secret": "Vt-GWFmR088SlNCOtaEtztNl", "revoke_uri": "https://accounts.google.com/o/oauth2/revoke", "_class": "OAuth2Credentials", "refresh_token": "1/b59IfWyeEYvYtPyJv3NMazOV78Tofa6qEvhifJSFu7mhobZ1Ve6FazoB6stxXQ76", "user_agent": null}')
drive2 = GoogleDrive(gauth2)
'''


def get_token(userID, gui=None):
    # oauth = raw_input("get key?")
    # if oauth == 'y':
    gauth = GoogleAuth()
    gauth.LocalWebserverAuth()
    file = open("credentials.json", "r")
    credentials = file.read()
    if gui:
        name = tkSimpleDialog.askstring('', "What do you want to name this dirve? ")
    else:
        name = raw_input("What do you want to name this dirve? ")

    try:
        print addkey(name, encrypt_string(credentials), userID, 'google')
    except e:
        print e
        print "Duplicate account"

    os.remove("credentials.json")

def encrypt_string(string):
    BLOCK_SIZE = 16
    PADDING = '{'
    pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
    EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
    print get_mac()
    macaddr = str(get_mac())
    while len(macaddr) < 16:
        macaddr += '0'
    print macaddr
    cipher = AES.new(macaddr)

    return EncodeAES(cipher, string)

def decrypt_string(string):
    BLOCK_SIZE = 16
    PADDING = '{'
    pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
    DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
    macaddr = str(get_mac())
    while len(macaddr) < 16:
        macaddr += '0'
    cipher = AES.new(macaddr)
    return DecodeAES(cipher, string)

class pycloud():

    def __init__(self,account_dict = None, account_name= None, userID= None):
        self.account_dict = account_dict
        self.account_name = account_name
        self.userID = userID
        if userID != None:
            gauth = GoogleAuth()
            gauth.credentials = OAuth2Credentials.from_json(decrypt_string(account_dict[account_name]['token']))
            global drive
            self.drive = GoogleDrive(gauth)
        if account_dict:
            gauth = GoogleAuth()
            gauth.credentials = OAuth2Credentials.from_json(decrypt_string(account_dict[account_name]['token']))
            global drive
            drive = GoogleDrive(gauth)

    global current_dir
    global dir_list
    drive = ''

    def derive_key_and_iv(self,password, salt, key_length, iv_length):
        d = d_i = ''
        while len(d) < key_length + iv_length:
            d_i = md5(d_i + password + salt).digest()
            d += d_i
        return d[:key_length], d[key_length:key_length+iv_length]

    def encrypt(self,in_file, out_file, password, key_length=32):
        with open(in_file, 'rb') as in_file, open('data_buffer/' + out_file, 'wb') as out_file:
            bs = AES.block_size
            salt = Random.new().read(bs - len('Salted__'))
            key, iv = self.derive_key_and_iv(password, salt, key_length, bs)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            out_file.write('Salted__' + salt)
            finished = False
            while not finished:
                chunk = in_file.read(1024 * bs)
                if len(chunk) == 0 or len(chunk) % bs != 0:
                    padding_length = bs - (len(chunk) % bs)
                    chunk += padding_length * chr(padding_length)
                    finished = True
                out_file.write(cipher.encrypt(chunk))


    def decrypt(self,in_file, out_file, password, key_length=32):
        with open(in_file, 'rb') as in_file, open(out_file, 'wb') as out_file:
            bs = AES.block_size
            salt = in_file.read(bs)[len('Salted__'):]
            key, iv = self.derive_key_and_iv(password, salt, key_length, bs)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            next_chunk = ''
            finished = False
            while not finished:
                chunk, next_chunk = next_chunk, cipher.decrypt(in_file.read(1024 * bs))
                if len(next_chunk) == 0:
                    padding_length = ord(chunk[-1])
                    if padding_length < 1 or padding_length > bs:
                       raise ValueError("bad decrypt pad (%d)" % padding_length)
                    # all the pad-bytes must be the same
                    if chunk[-padding_length:] != (padding_length * chr(padding_length)):
                       # this is similar to the bad decrypt:evp_enc.c from openssl program
                       raise ValueError("bad decrypt")
                    chunk = chunk[:-padding_length]
                    finished = True
                out_file.write(chunk)

    def get_command(self):
        handle_input = raw_input(JColor.BOLDON + JColor.FGCYAN + "\n>> " + JColor.ENDC + JColor.BOLDOFF)
        return handle_input

    def return_id_by_name(self, name, dir_list):
        print "find ID"
        if name == '..':
            parentID = dir_list.GetList()[0]["parents"][0]['id']
            parentsDIR = drive.CreateFile({'id': parentID})
            return parentsDIR["parents"][0]['id']

        for file_list in dir_list:
            for file1 in file_list:
                if file1['title'] == name:
                    return file1['id']

    def is_folder(self,file):
        """
        check if a file is folder
        :param file:
        :return:
        """
        if 'folder' in file['mimeType']:
            return True
        else:
            return False

    def print_dir(self, foldername, dir_list):


        # i hate these kinds of things, i really do
        #     this was such a pain for me to figure out
        # in case you are wondering, i'm looping through the folder dict
        #     and pulling out the names so they can be displayed

        query = {
            'q': "'" + foldername + "'" + ' in parents and trashed=false'
        }

        #file_list = drive.ListFile({'q': "'" + 'root' + "'" + ' in parents'}).GetList()
        dir_list = drive.ListFile({'q': "'" + foldername + "'" + ' in parents and trashed=false'})
        for file_list in dir_list:
            #print('Received %s files from Files.list()' % len(file_list))  # <= 10
            for file1 in file_list:
                #print('title: %s, id: %s PATH: %s' % (file1['title'], file1['id'], file1['parents']))
                print JColor.FGORANGE + '/%s' % file1['title'] + JColor.ENDC
        dir_list = drive.ListFile({'q': "'" + foldername + "'" + ' in parents'})
        #return dir_list.GetList()
        return dir_list

    def creat_folder(self,current_dir, foldername):
        # Create folder
        folder_metadata = {'title': foldername, 'parents': [{'id': current_dir}] ,'mimeType': 'application/vnd.google-apps.folder'}
        folder = drive.CreateFile(metadata=folder_metadata)
        folder.Upload()

    def upload(self,remote_folder, local_file, otherdr = None, parent_name = None, parent_parent_id = None):
        """
        upload a file to a drive folder
        :param local_file: path to local file
        :param remote_folder: remote folder id
        :return: file's metadata
        """
        metadata = {
            'title': os.path.basename(local_file),
            'parents': [{'id': remote_folder}]
        }
        if otherdr != None:
            file = otherdr.CreateFile(metadata=metadata)
            file.SetContentFile(local_file.replace(".merge", ""))
            try:
                file.Upload()
            except:
                print 'filder not exist'
                '''
                metadata = {
                    'title': os.path.basename(local_file),
                    'parents': [{'id': remote_folder}],
                    "mimeType": "application/vnd.google-apps.folder"
                }
                file2 = otherdr.CreateFile(metadata=metadata)
                #file.SetContentFile(local_file)
                file2.Upload()
                '''
                folder_metadata = {'title': parent_name, 'parents': [{'id': parent_parent_id}],
                                   'mimeType': 'application/vnd.google-apps.folder'}
                folder = otherdr.CreateFile(metadata=folder_metadata)
                folder.Upload()
                dir_tree = otherdr.ListFile({'q': 'trashed=false', 'maxResults': 1000})
                remote_folder = self.return_id_by_name(parent_name, dir_tree)
                metadata = {
                    'title': os.path.basename(local_file),
                    'parents': [{'id': remote_folder}]
                }
                file = otherdr.CreateFile(metadata=metadata)
                file.SetContentFile(local_file)
                file.Upload()
            print(os.path.basename(local_file), 'uploaded to google drive at', remote_folder)
            return file.metadata
        else:
            file = drive.CreateFile(metadata=metadata)
            file.SetContentFile(local_file)
            file.Upload()
            print(os.path.basename(local_file), 'uploaded to google drive at', remote_folder)
            return file.metadata

    def download(self,remote_file, dir_tree, path_override = None):
        fileID = self.return_id_by_name(remote_file.replace(".merge", ""), dir_tree)
        print 'test'
        print remote_file, fileID
        metadata = {
            'id': fileID
        }
        file = drive.CreateFile(metadata=metadata)
        print 'title', file['title']
        if path_override != None:
            file.GetContentFile(os.path.join(path_override, file['title']))
        else:
            file.GetContentFile(os.path.join('download', file['title']))
        if (remote_file[-4:] == ".enc"):
            print "start de"
            self.decrypt('data_buffer/' + remote_file, 'download/' + os.path.splitext(remote_file)[0], str(get_mac()))
        print(file['title'], 'downloaded from google drive to', '/download')
        return file.metadata

    def copy(self,local_file, remote_folder, dir_tree):
        print local_file + remote_folder
        remote_folder = self.return_id_by_name(remote_folder, dir_tree)
        dir_tree = drive.ListFile({'q': 'trashed=false', 'maxResults': 1000})
        file = self.return_id_by_name(local_file, dir_tree)
        print remote_folder
        print file
        drive.auth.service.files().copy(fileId=file,
                                        body={"parents": [{"kind": "drive#fileLink",
                                                           "id": remote_folder}], 'title': local_file}).execute()

    def delete(self,remote_file, dir_list):
        fileID = self.return_id_by_name(remote_file, dir_list)
        file = drive.CreateFile({'id': fileID})
        file.Delete()

    def othergd(self,remote_file, dir_list, account_dict, account_name):
        def check_filesize(current_dir, name_of_file, client):

            # list client folders
            folder_metadata = client.metadata(current_dir)

            # store folders in a dict
            folder_metadata_dict = folder_metadata
            for key, value in folder_metadata_dict.iteritems():
                # print value
                if type(value) is list:
                    for listitem in value:
                        if type(listitem) is dict:
                            # print listitem
                            for nested_key, nested_value in listitem.iteritems():
                                # print "looping through data"
                                if (nested_key == 'path'):
                                    # print "found path" + nested_value
                                    if (nested_value == (current_dir + "/" + name_of_file)) or (
                                        nested_value.lower() == current_dir + "/" + name_of_file.lower()):
                                        current_dir = nested_value
                                        if name_of_file in current_dir:
                                            current_dir = current_dir.replace(name_of_file, "")
                                        print current_dir + name_of_file + ": " + str(listitem['bytes']) + " bytes"
                                        file_size = listitem['bytes']
                                        return str(file_size) + " bytes"
                                    elif (nested_value == "/" + name_of_file) or (
                                        nested_value.lower() == "/" + name_of_file):
                                        current_dir = nested_value
                                        if name_of_file in current_dir:
                                            current_dir = current_dir.replace(name_of_file, "")
                                        current_dir = "/"
                                        print current_dir + name_of_file + ": " + str(listitem['bytes']) + " bytes"
                                        file_size = listitem['bytes']
                                        return str(file_size) + " bytes"
        def encrypt_file(key, in_filename, out_filename=None, chunksize=64 * 1024):
            """ Encrypts a file using AES (CBC mode) with the
                given key.
    
                key:
                    The encryption key - a string that must be
                    either 16, 24 or 32 bytes long. Longer keys
                    are more secure.
    
                in_filename:
                    Name of the input file
    
                out_filename:
                    If None, '<in_filename>.enc' will be used.
    
                chunksize:
                    Sets the size of the chunk which the function
                    uses to read and encrypt the file. Larger chunk
                    sizes can be faster for some files and machines.
                    chunksize must be divisible by 16.
            """
            if not out_filename:
                out_filename = in_filename + '.enc'

            iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
            encryptor = AES.new(key, AES.MODE_CBC, iv)
            filesize = os.path.getsize(in_filename)

            with open(in_filename, 'rb') as infile:
                with open(out_filename, 'wb') as outfile:
                    outfile.write(struct.pack('<Q', filesize))
                    outfile.write(iv)

                    while True:
                        chunk = infile.read(chunksize)
                        if len(chunk) == 0:
                            break
                        elif len(chunk) % 16 != 0:
                            chunk += ' ' * (16 - len(chunk) % 16)

                        outfile.write(encryptor.encrypt(chunk))

        def decrypt_file(key, in_filename, out_filename=None, chunksize=24 * 1024):
            """ Decrypts a file using AES (CBC mode) with the
                given key. Parameters are similar to encrypt_file,
                with one difference: out_filename, if not supplied
                will be in_filename without its last extension
                (i.e. if in_filename is 'aaa.zip.enc' then
                out_filename will be 'aaa.zip')
            """
            if not out_filename:
                out_filename = os.path.splitext(in_filename)[0]

            with open(in_filename, 'rb') as infile:
                origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
                iv = infile.read(16)
                decryptor = AES.new(key, AES.MODE_CBC, iv)

                with open(out_filename, 'wb') as outfile:
                    while True:
                        chunk = infile.read(chunksize)
                        if len(chunk) == 0:
                            break
                        outfile.write(decryptor.decrypt(chunk))

                    outfile.truncate(origsize)

        # for uploading files
        def new_upload(current_dir, path_to_file, upload_file_name, encrypt, client):
            new_file_name = current_dir + "/" + upload_file_name
            local_file_size = os.stat(path_to_file).st_size

            # if file is bigger than or equal to 4MB
            #     use the chunked uploader (apparently
            #     better for bigger files)
            # else
            #     use the regular put_file() function
            if (local_file_size >= 4194304):
                print "uploading " + path_to_file + " to " + current_dir
                big_file = open(path_to_file, 'rb')
                if (encrypt == "true"):
                    print 'start encrypting'
                    encrypt_file("0000000000000000", path_to_file)
                    ef = open(path_to_file + '.enc', 'rb')
                    uploader = client.get_chunked_uploader(ef, local_file_size)
                    while uploader.offset < local_file_size:
                        try:
                            upload = uploader.upload_chunked()
                        except rest.ErrorResponse, e:
                            # perform error handling and retry logic
                            print e
                            raise
                    uploader.finish(current_dir + "/" + upload_file_name + '.enc', True)
                    os.remove(path_to_file + '.enc')  # delete encrypted file
                else:
                    print 'no encrypting'
                    uploader = client.get_chunked_uploader(big_file, local_file_size)
                    while uploader.offset < local_file_size:
                        try:
                            upload = uploader.upload_chunked()
                        except rest.ErrorResponse, e:
                            # perform error handling and retry logic
                            print e
                            raise
                    uploader.finish(current_dir + "/" + upload_file_name, True)
                clearscreen()
                #print_dir(access_token, user_id, current_dir)
                print "[+]\tsuccessfully uploaded " + upload_file_name
                # upload_file_size = check_filesize(current_dir, upload_file_name, client)
                #  print "uploaded " + convert_bytes(upload_file_size) + " of " + convert_bytes(local_file_size)
                # print "[+]\tsuccessfully uploaded " + upload_file_name + " to " + current_dir
            else:
                #try:
                f = open(path_to_file, 'rb')
                if (encrypt == "true"):
                    encrypt_file("0000000000000000", path_to_file)
                    ef = open(path_to_file + '.enc', 'rb')
                    target = client.put_file(current_dir + "/" + upload_file_name + '.enc', ef, True)
                    upload_file_size = check_filesize(current_dir, upload_file_name, client)
                    os.remove(path_to_file + '.enc')  # delete encrypted file
                else:
                    print 'no encrypting'
                    target = client.put_file(current_dir + "/" + upload_file_name, f, True)
                    #upload_file_size = check_filesize(current_dir, upload_file_name, client)
                '''
                except res.ErrorResponse, e:
                    print e
                    raise
                    # print "uploaded " + convert_bytes(upload_file_size) + " of " + convert_bytes(local_file_size)
                '''
                clearscreen()
                #print_dir(access_token, user_id, current_dir)
                print "[+]\tsuccessfully uploaded " + upload_file_name

                # function to copy files
        self.download(remote_file, dir_list, 'data_buffer')
        type = account_dict[account_name]['type']
        if type == 'dropbox':
            client2 = dropbox.client.DropboxClient(account_dict[account_name]['token'])
            print remote_file
            new_upload('/', 'data_buffer/' + remote_file, remote_file, 'no', client2)
        elif type == 'google':
            gauth = GoogleAuth()
            gauth.credentials = OAuth2Credentials.from_json(account_dict[account_name]['token'])
            drive = GoogleDrive(gauth)
            self.upload('root', 'data_buffer/' + remote_file, drive)

    def account_selection(self,userID, gui = None):
        if  gui:
            global account_name

            def ok(account_list, account_dict):
                global account_name
                account_index = account_list.curselection()
                account_name = account_list.get(account_index)
                account_sel_window.quit()
                #account_sel_window.destroy()

                #return account_dict, account_name

            account_dict = get_account(userID)
            account_sel_window = Tk()  # Opens new window
            account_sel_window.title('select account')
            account_sel_window.geometry()  # Makes the window a certain size

            account_dict = get_account(userID)
            account_list = Listbox(account_sel_window)
            account_list.pack()
            for account, values in account_dict.items():
                account_list.insert(END, account)
            print account_list
            dir_load_bt = Button(account_sel_window, text="OK",
                                 command=lambda: ok(account_list, account_dict)).pack()
            account_sel_window.mainloop()
            account_sel_window.destroy()

            return account_dict, account_name

        else:
            account_dict = get_account(userID)
            choices = []
            for account, values in account_dict.items():
                choices.append(account)

            #account_name = raw_input("Which drive do you want to connect?")

            questions = [
                inquirer.List('drive',
                              message="Which drive do you want to connect?",
                              choices= choices,
                              ),
            ]
            account_name = inquirer.prompt(questions)
            #print account_name

            return account_dict, account_name['drive']

    def get_checksum(self,file_path):
        BUF_SIZE = 65536
        md5 = hashlib.md5()
        with open(file_path, 'rb') as f:
            while True:
                data = f.read(BUF_SIZE)
                if not data:
                    break
                md5.update(data)

        return md5.hexdigest()

    def merge(self,userID, gui = None):
        def read_dir(drive, dir_dict, level, newlist, foldername, path):
            folderID = ''
            print foldername

            if foldername == 'root':
                #dir_tree = drive.ListFile({'q': "'" + foldername + "'" + 'trashed=false', 'maxResults': 1000})
                dir_tree = drive.ListFile({'q': "'root' in parents and trashed=false"})

            else:
                #print 'start subfolder', foldername

                folderID = self.return_id_by_name(foldername, dir_dict)
                #print 'befroe tree', folderID
                dir_tree = drive.ListFile({'q': "'" + folderID + "'" + ' in parents and trashed=false'})
                '''
                for file_list in dir_tree:
                    #print('Received %s files from Files.list()' % len(file_list))  # <= 10
                    for file1 in file_list:
                        #print('title: %s, id: %s PATH: %s' % (file1['title'], file1['id'], file1['parents']))
                        #print JColor.FGORANGE + '/%s' % file1['title'] + JColor.ENDC
                dir_tree = drive.ListFile({'q': "'" + folderID + "'" + ' in parents and trashed=false'})
                '''


                '''
                print "id", folderID
                dir_tree = drive.ListFile({'q': "'root' in parents and trashed=false"}) 
                dir_tree = drive.ListFile({'q': "'" + current_dir + "'" + 'in parents and trashed=false'}).GetList()
                '''
                '''
                folderID = return_id_by_name(foldername, dir_dict)
                dir_list = print_dir(current_dir, dir_dict)
                print current_dir
                '''
            print dir_tree
            for file_list in dir_tree:
                for file1 in file_list:
                    #print file1['title']
                    metadata = {
                        'id': file1['id']
                    }
                    file = drive.CreateFile(metadata=metadata)
                    file_metadata = file.metadata
                    isFolder = 'False'
                    if 'folder' in file1['mimeType']:
                        isFolder = 'True'
                    if isFolder == 'False':
                        if level in newlist:
                            newlist[level].update({file1['id']: path + '/' + foldername + '/' + file1['title']})
                        else:
                            newlist[level] = ({file1['id'] : path + '/' + foldername + '/' + file1['title']})
                        #newlist.append({level: [file1['id'], path + '/' + foldername + '/' + file1['title']]})
                        #print newlist
                    if isFolder == 'True':
                        metadata = {
                            'id': file1['id']
                        }
                        file = drive.CreateFile(metadata=metadata)
                        file_metadata = file.metadata
                        #print 'level', level
                        if level > 1:
                            dir_tree = drive.ListFile({'q': "'" + folderID + "'" + ' in parents and trashed=false'})
                        else:
                            dir_tree = drive.ListFile({'q': "'root' in parents and trashed=false"})
                        read_dir(drive, dir_tree, level+1, newlist, file1['title'], path + '/' + foldername)
            return newlist
        '''
            for key, value in metadata.iteritems():
                if type(value) is list:
                    for listitem in value:
                        if listitem['is_dir'] == False:
                            newlist.append(listitem['path'])
                        if listitem['is_dir'] == True:
                            metadata = client.metadata(listitem['path'])
                            read_dir(metadata, dir_dict, level, newlist)
                    dir_dict[level] = newlist
                    # print dir_dict
            return dir_dict
        '''
        if gui == None:
            account_dict, account_name = self.account_selection(userID)
        else:
            account_dict, account_name = self.account_selection(userID, True)
        gauth = GoogleAuth()
        gauth.credentials = OAuth2Credentials.from_json(decrypt_string(account_dict[account_name]['token']))
        drive2 = GoogleDrive(gauth)
        #client2 = dropbox.client.DropboxClient(account_dict[account_name]['token'])
        #dir_tree = drive.ListFile({'q': "'" + '/' + "'" + 'in parents and trashed=false'})
        dir_tree = drive.ListFile({'q': "'root' in parents and trashed=false"})
        level = 1
        src_list = dict()
        des_list = dict()
        src_list = read_dir(drive, dir_tree, level, src_list, 'root', '')
        des_list = read_dir(drive2, dir_tree, level, des_list, 'root', '')
        #src_list.sort()
        print src_list
        #des_list.sort()
        print des_list
        src_list_cp = deepcopy(src_list)
        des_list_cp = deepcopy(des_list)
        for src_level, src_level_value in src_list_cp.iteritems():
            for src_key, src_values in src_level_value.iteritems():
                for des_level, des_level_value in des_list_cp.iteritems():
                    for des_key, des_values in des_level_value.iteritems():
                        if src_level == des_level and src_values == des_values:
                            metadata = {
                                'id': src_key
                            }
                            file = drive.CreateFile(metadata=metadata)
                            naem = file['title']
                            file_metadata = file.metadata
                            # print file_metadata
                            # checksum = file_metadata['md5Checksum']
                            checksum1 = file_metadata['md5Checksum']
                            print 'checksum: ' + checksum1

                            metadata = {
                                'id': des_key
                            }
                            file = drive2.CreateFile(metadata=metadata)
                            naem = file['title']
                            file_metadata = file.metadata
                            # print file_metadata
                            # checksum = file_metadata['md5Checksum']
                            checksum2 = file_metadata['md5Checksum']
                            print 'checksum: ' + checksum2
                            if checksum1 == checksum2:
                                print src_values + ' same'
                                print len(src_list_cp[src_level])
                                print 'test'
                                print src_level
                                print src_key
                                del src_list[src_level][src_key]
                                print len(src_list_cp[src_level])
                            else:
                                del src_list[src_level][src_key]
                                src_list[src_level].update({src_key: src_values + '.merge'})
                                #print 'test', src_list.iteritems()[src_key]


                            '''
                            print src_values[0]
                            metadata1 = {
                                'id': src_values[0]
                            }
                            metadata2 = {
                                'id': des_values[0]
                            }
                            file1 = drive.CreateFile(metadata=metadata1)
                            file2 = drive2.CreateFile(metadata=metadata2)
                            file_metadata1 = file1.metadata
                            print file_metadata1
                            file_metadata2 = file2.metadata
                            checksum1 = file_metadata1['md5Checksum']
                            checksum2 = file_metadata2['md5Checksum']
                            if checksum1 == checksum2:
                                print src_values[1] + ' same'
                            '''
        print 'after check: ', src_list
        for level, level_values in src_list.iteritems():
            for key, values in level_values.iteritems():
                print 'name ', ntpath.basename(values)
                name = ntpath.basename(values)
                print 'id', key
                id = key
                print 'path ', values
                path = values
                print 'parent_name', values.replace(ntpath.basename(values), '')[values.replace('/' + ntpath.basename(values), '').rfind('/')+1:-1]
                parent_name = values.replace(ntpath.basename(values), '')[values.replace('/' + ntpath.basename(values), '').rfind('/')+1:-1]
                print 'parent_parent_name', values.replace(parent_name+'/'+name, '')[values.replace('/'+parent_name+'/'+name, '').rfind('/')+1:-1]
                parent_parent_name = values.replace(parent_name+'/'+name, '')[values.replace('/'+parent_name+'/'+name, '').rfind('/')+1:-1]

                #x.rsplit('-', 1)[0]
                if level == 1:
                    dir_tree = drive.ListFile({'q': 'trashed=false', 'maxResults': 1000})
                    self.download(name, dir_tree, 'data_buffer')
                    print self.upload('root', 'data_buffer/' + name, drive2)
                elif level == 2:
                    print 'key', key
                    #print upload(values[0], ntpath.basename(values[1]), drive2)
                    dir_tree = drive.ListFile({'q': 'trashed=false', 'maxResults': 1000})
                    self.download(name, dir_tree, 'data_buffer')
                    dir_tree = drive2.ListFile({'q': 'trashed=false', 'maxResults': 1000})
                    parent_id = self.return_id_by_name(parent_name, dir_tree)

                    print self.upload(parent_id, 'data_buffer/' + name, drive2, parent_name, 'root')
                else:
                    dir_tree = drive.ListFile({'q': 'trashed=false', 'maxResults': 1000})
                    self.download(name, dir_tree, 'data_buffer')
                    dir_tree = drive2.ListFile({'q': 'trashed=false', 'maxResults': 1000})
                    parent_id = self.return_id_by_name(parent_name, dir_tree)
                    dir_tree = drive2.ListFile({'q': 'trashed=false', 'maxResults': 1000})
                    parent_parent_id = self.return_id_by_name(parent_parent_name, dir_tree)
                    print 'parent_parent_id ' + parent_parent_id
                    print self.upload(parent_id, 'data_buffer/' + name, drive2, parent_name, parent_parent_id)
            self.clean_data_buffer()

    def clean_data_buffer(self):
        filelist = [f for f in os.listdir("data_buffer")]
        for f in filelist:
            os.remove("data_buffer/" + f)


        '''
        print file_metadata
        print file1['title']
        isFolder = 'False'
        if 'folder' in file1['mimeType']:
            isFolder = 'True'
        print 'folder?: ' + isFolder
        print "self ID: " + file1['id']
        print 'parent ID: ' + file1['parents'][0]['id']
        if isFolder == 'False':
            metadata = {
                'id': file1['id']
            }
            file = drive.CreateFile(metadata=metadata)
            print 'title', file['title']
            file_metadata = file.metadata
            #print file_metadata
            #checksum = file_metadata['md5Checksum']
            checksum = file_metadata['md5Checksum']
            print 'checksum: ' + checksum
            #return file.metadata
                '''
        '''
        metadata = {
            'id': file1['id']
        }
        
        file = drive.CreateFile(metadata=metadata)
        file.GetContentFile
        file_metadata = file.metadata
        #checksum = file_metadata['md5Checksum']
        #print 'checksum: ' + checksum
        print file_metadata
        '''

    def load_dir(self, account_dict, account_name, userID):
        cout = True
        gauth = GoogleAuth()
        gauth.credentials = OAuth2Credentials.from_json(account_dict[account_name]['token'])
        global drive
        drive = GoogleDrive(gauth)
        current_dir = "root"
        dir_list = ''

        while (cout):
            dir_tree = drive.ListFile({'q': 'trashed=false', 'maxResults': 1000})
            print "cur dir: ", current_dir
            dir_list = self.print_dir(current_dir, dir_list)
            # get the very first input, the program will loop back to this each
            #     time the a conditional finishes executing
            handle_input = self.get_command()
            if 'ls' in handle_input:
                try:
                    self.print_dir(current_dir, dir_list)
                    clearscreen()
                    #print dir_list
                except Exception as ex:
                    print (str(ex))
            elif 'cd' in handle_input:
                try:
                    # scrub out what was entered in so we are left with only the argument to process
                    handle_input = handle_input.replace("cd", "")
                    # strip away any whitespaces
                    handle_input = handle_input.strip()
                    # if we are in the root directory set the new directory to the root "/" + what was just entered
                    # for example: cd work will change from the root or / to /work
                    current_dir = self.return_id_by_name(handle_input, dir_list)
                    dir_list = self.print_dir(current_dir, dir_list)
                    print current_dir
                    clearscreen()

                    #print_dir(current_dir, dir_list)
                    # current_dir = handle_input
                    # current_dir = current_dir + "/" + handle_input
                    # get_command()
                except Exception as ex:
                    print 'cant find ' + handle_input
                    current_dir = "root"
                    # print_dir(access_token, user_id, "/")
                    print (str(ex))
            elif 'mkdir' in handle_input:
                handle_input = handle_input.replace("mkdir", "")
                handle_input = handle_input.replace("'", "").strip()
                handle_input = handle_input.split()
                self.creat_folder(current_dir, handle_input[0])
                clearscreen()
            elif 'upload' in handle_input and ('-e' not in handle_input) and ('-m' not in handle_input):
                handle_input = handle_input.replace("upload", "")
                handle_input = handle_input.replace("'", "").strip()
                handle_input = handle_input.split()
                print self.upload(current_dir, handle_input[0])
            elif 'upload -e' in handle_input:
                handle_input = handle_input.replace("upload -e", "")
                handle_input = handle_input.replace("'", "").strip()
                handle_input = handle_input.split()
                self.encrypt(handle_input[0], handle_input[0]+'.enc', str(get_mac()))
                self.upload(current_dir, 'data_buffer/'+handle_input[0]+'.enc')
            elif 'upload -m' in handle_input:
                root = Tkinter.Tk()
                filez = tkFileDialog.askopenfilenames(parent=root, title='Choose a file')
                for file in root.tk.splitlist(filez):

                    success = False
                    while (success == False):
                        dir_tree = drive.ListFile({'q': 'trashed=false', 'maxResults': 1000})
                        metadata = self.upload(current_dir, file)
                        checksum = metadata['md5Checksum']
                        print checksum
                        print self.get_checksum(file)
                        if self.get_checksum(file) == checksum:
                            success = True
                root.withdraw()
            elif 'cp' in handle_input:
                handle_input = handle_input.replace("cp", "")
                handle_input = handle_input.replace("'", "").strip()
                handle_input = handle_input.split()
                self.copy(handle_input[0], handle_input[1], dir_tree)
            elif 'rm' in handle_input:
                handle_input = handle_input.replace("rm", "")
                handle_input = handle_input.replace("'", "").strip()
                handle_input = handle_input.split()
                self.delete(handle_input[0], dir_tree)
                clearscreen()
            elif 'dl' in handle_input and ('-m' not in handle_input):
                handle_input = handle_input.replace("dl", "")
                handle_input = handle_input.replace("'", "").strip()
                handle_input = handle_input.split()
                self.download(handle_input[0], dir_tree)
            elif 'dl -m' in handle_input:
                handle_input = handle_input.replace("dl -m", "")
                handle_input = handle_input.replace("'", "").strip()
                handle_input = handle_input.split()
                dl_list = []
                myroot = Tk()
                l = Listbox(myroot, selectmode='multiple')
                l.pack()
                for file_list in dir_list:
                    for file1 in file_list:
                        # print('title: %s, id: %s PATH: %s' % (file1['title'], file1['id'], file1['parents']))
                        l.insert(END, file1['title'])

                def get_dl_list(l, myroot, dl_list):
                    #global l, myroot, dl_list
                    #dl_list = []
                    #myroot = Tk()
                    #l = Listbox(myroot, selectmode='multiple')
                    items = l.curselection()
                    for i in items:
                        #file_name = l.get(i).replace("'", "").replace("u", "")
                        #dl_list.append(file_name)
                        dl_list.append(l.get(i))
                    myroot.destroy()
                    #root.withdraw()
                    #print dl_list
                b = Button(myroot, text="OK", command= lambda: get_dl_list(l, myroot, dl_list)).pack()
                myroot.mainloop()

                for file in dl_list:
                    success = False
                    while(success == False):
                        dir_tree = drive.ListFile({'q': 'trashed=false', 'maxResults': 1000})
                        metadata = self.download(file, dir_tree)
                        checksum = metadata['md5Checksum']
                        print checksum
                        print self.get_checksum('download/' + file)
                        if self.get_checksum('download/' + file) == checksum:
                            success = True
            elif 'othergd' in handle_input:
                handle_input = handle_input.replace("othergd", "")
                handle_input = handle_input.replace("'", "").strip()
                handle_input = handle_input.split()
                account_dict, account_name = account_selection(userID)
                self.othergd(handle_input[0], dir_tree,account_dict, account_name)
                self.clean_data_buffer()
            elif 'merge' in handle_input:
                self.merge(userID)
            elif 'switch' in handle_input:
                cout = False
            elif 'exit' in handle_input:
                sys.exit()

'''
#username = raw_input("username: ")
#password = raw_input("password: ")
username = 'testuser'
password = 'test'
(success, userID) = login(username, password)
if success:
    print 'success login'
    print userID
else:
    print 'bye'
    sys.exit()

get_token()
'''
def main(account_dict, account_name, userID):
    home_screen('CLEMENS')
    py = pycloud()
    py.load_dir(account_dict, account_name, userID)
