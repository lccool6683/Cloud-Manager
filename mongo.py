import sys
from Tkconstants import END

from pymongo import MongoClient
client = MongoClient()

client = MongoClient('mongodb://user:1234@ds019846.mlab.com:19846/cloud_manager')
db = client.cloud_manager


def login(name, password, dbCollectionName="user"):
    """string name, string password, string dbname="users",
    string collection="people"
    sets authenticated to True for a given user"""
    success = False

    people = db[dbCollectionName]

    if (isInDatabase(name, dbCollectionName)):
        # should only loop through once
        for user in people.find({"username": name}):
            if (user['password'] == password):
                success = True
                #print user['_id']
                return success, user['_id']
    return success, None

def get_account(userID, dbCollectionName="key"):
    account = db[dbCollectionName]
    account_dict = {}
    # should only loop through once
    for account in account.find({"userID": userID}):
        #account_dict.append(account)
        account_dict[account['name']] = account
    return account_dict

def isInDatabase(name, dbCollectionName="user"):
    """takes string name, string dbname, string dbCollectionName
    checks if user is already in the database and returns False if username
    already exists"""

    # returns collection of users
    people = db[dbCollectionName]

    # there should be at most one instance of the user in the database
    success = (people.find({"username": name}).count() == 1)
    return success

def addUser(name, password, dbCollectionName="user"):
    """string name, string password, string dbname, string dbCollectionName
    adds user to the database and returns False is username already exists
    automatically logs the user in after creating the account"""
    success = True


    if (not isInDatabase(name, dbCollectionName)):
        # Jsonifies the User, authenticated True means the user is logged in
        user = {'username': name,
                'password': password}
        people = db[dbCollectionName]
        people.insert(user)
        print 'Account created successfully'
    else:
        print "This username is taken"
        success = False

    return success

def addkey(name, token, userId, cloud_type, dbCollectionName="key"):
    """string name, string password, string dbname, string dbCollectionName
    adds user to the database and returns False is username already exists
    automatically logs the user in after creating the account"""
    success = False

    # Jsonifies the User, authenticated True means the user is logged in
    try:
        user = {'token': token,
                'type': cloud_type,
                'userID': userId,
                'name': name}
        people = db[dbCollectionName]
        people.insert(user)
        success = True
    except:
        print 'error'


    return success

#print login(sys.argv[1], sys.argv[2])
#print addUser(sys.argv[1], sys.argv[2])

def delkey(userID, account_list, dbCollectionName="key"):
    people = db[dbCollectionName]
    account_index = account_list.curselection()
    account_name = account_list.get(account_index)
    for key in people.find({'userID': userID, 'name': account_name}):
        print(key)
        people.remove(key)
    account_dict = get_account(userID)
    account_list.delete(0, END)
    for account, values in account_dict.items():
        account_list.insert(END, account)