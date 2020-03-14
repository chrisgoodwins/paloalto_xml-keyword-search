###############################################################################
#
# Script:       xml-keyword-search.py
#
# Author:       Chris Goodwin <chrisgoodwins@gmail.com>
#
# Description:  This script will allow a user to pull a config from
#               Panorama/firewall once authenticated, then search for a keyword
#               string, and return the xpath containing the string if the it
#               was found. The output is separated by xpaths where the string
#               was found in the tag's attributes and where the string was
#               found in the tag's text. You will then have the option to view
#               children of the tag in the xpath.
#
# Usage:        xml-keyword-search.py
#
# Requirements: requests, beautifulsoup4
#
# Python:       Version 3
#
###############################################################################
###############################################################################


import getpass
import re
import time
from xml.etree import ElementTree as ET
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    raise ValueError("requests support not available, please install module - run 'py -m pip install requests'")
try:
    from bs4 import BeautifulSoup
except ImportError:
    raise ValueError("BeautifulSoup support not available, please install module - run 'py -m pip install beautifulsoup4'")


###############################################################################
###############################################################################


# Prompts the user to enter an address, then checks it's validity
def getfwipfqdn():
    while True:
        fwipraw = input('\nPlease enter Panorama/firewall IP or FQDN: ')
        ipr = re.match(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$', fwipraw)
        fqdnr = re.match(r'(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)', fwipraw)
        if ipr:
            break
        elif fqdnr:
            break
        else:
            print('\nThere was something wrong with your entry. Please try again...\n')
    return fwipraw


# Prompts the user to enter a username and password
def getCreds():
    while True:
        username = input('Please enter your user name: ')
        usernamer = re.match(r'^[\w-]{3,24}$', username)
        if usernamer:
            password = getpass.getpass('Please enter your password: ')
            break
        else:
            print('\nThere was something wrong with your entry. Please try again...\n')
    return username, password


# Retrieves the user's api key
def getkey(fwip):
    while True:
        try:
            username, password = getCreds()
            keycall = f'https://{fwip}/api/?type=keygen&user={username}&password={password}'
            r = requests.get(keycall, verify=False)
            tree = ET.fromstring(r.text)
            if tree.get('status') == 'success':
                apikey = tree.find('./result/key').text
                break
            else:
                print('\nYou have entered an incorrect username or password. Please try again...\n')
        except requests.exceptions.ConnectionError:
            print('\nThere was a problem connecting to the firewall. Please check the address and try again...\n')
            exit()
    return apikey


# Searches XML file for tags which contain the keyword, finds its parents up the path, and returns a
# list of xpaths from tag matches, and a dictionary containing each tag match along with its xpath
def tagSearch(tree, keyword):
    tagsDict = {}
    tagsList = []
    for tag in tree.find_all(re.compile(keyword)):
        parents_tag = []
        for parent in tag.find_parents():
            if parent.name == 'entry' and parent.name is not None and parent.get('name') != 'localhost.localdomain' and parent.get('name') != 'vsys1':
                parent.name = "entry[@name='" + parent.get('name') + "']"  # MATCH ON entry TAGS THAT HAVE AN ATTRIBUTE, AND PUT IT IN A STRING WITH PROPER FORMAT
            if parent.name != u'result' and parent.name != u'response' and parent.name != u'[document]':  # DON'T NEED THE TOP 3 PARENTS IN THE XML
                parents_tag.append(parent.name)
            children = tag.find_all()
            if len(children) == 0 and tag.text != '':
                tagsDict.update({parents_tag[0] + '/' + str(tag.name) + "[text()='" + str(tag.text) + "']": parents_tag[1:][::-1]})
            else:
                tagsDict.update({parents_tag[0] + '/' + str(tag.name): parents_tag[1:][::-1]})
        for key, value in tagsDict.items():  # LOOP THROUGH THE DICTIONARY AND CREATE THE XPATH STRING FOR EACH KEY
            xPath_tag = ''
            for item in value:  # LOOP THROUGH THE VALUES AND CREATE THE XPATH FROM THE PARENTS
                xPath_tag = xPath_tag + '/' + str(item)
            xPath_tag = xPath_tag + '/' + str(key)  # ADD THE KEY AT THE END OF THE XPATH, AFTER ALL THE PARENTS ARE ADDED
            tagsList.append(xPath_tag)
    tagsList = list(set(tagsList))
    tagsList.sort()
    return tagsDict, tagsList


# Searches XML file for tag attributes which contain the keyword, finds its parents up the path,
# and returns a list of xpaths from tag matches, and a dictionary containing each tag match along with its xpath
def attrSearch(tree, keyword):
    attrDict = {}
    attrList = []
    for attr in tree.find_all(attrs={"name": re.compile(keyword)}):
        parents_attr = []
        for parent in attr.find_parents():
            if parent.name == 'entry' and parent.name is not None and parent.get('name') != 'localhost.localdomain' and parent.get('name') != 'vsys1':
                parent.name = "entry[@name='" + parent.get('name') + "']"  # MATCH ON entry TAGS THAT HAVE AN ATTRIBUTE, AND PUT IT IN A STRING WITH PROPER FORMAT
            if parent.name != u'result' and parent.name != u'response' and parent.name != u'[document]':  # DON'T NEED THE TOP 3 PARENTS IN THE XML
                parents_attr.append(parent.name)
        if attr.name == u'entry':  # SOME TAG NAMES SHOW THE @name TAG AUTOMATICALLY, SO IT DUPLICATES BELOW. THIS FIXES THE DUPLICATE ISSUE ON THE ELSE STATEMENT
            attrDict.update({attr.name + "[@name='" + str(attr.get('name')) + "']": parents_attr[::-1]})
        else:
            attrDict.update({attr.name: parents_attr[::-1]})
        for key, value in attrDict.items():  # LOOP THROUGH THE DICTIONARY AND CREATE THE XPATH STRING FOR EACH KEY
            xPath_attr = ''
            for item in value:  # LOOP THROUGH THE VALUES AND CREATE THE XPATH FROM THE PARENTS
                xPath_attr = xPath_attr + '/' + str(item)
            xPath_attr = xPath_attr + '/' + str(key)  # ADD THE KEY AT THE END OF THE XPATH, AFTER ALL THE PARENTS ARE ADDED
            attrList.append(xPath_attr)
    attrList = list(set(attrList))
    attrList.sort()
    return attrDict, attrList


# Searches XML file for tag text which contains the keyword, finds its parents up the path,
# and returns a list of xpaths from tag matches, and a dictionary containing each tag match along with its xpath
def stringSearch(tree, keyword):
    stringDict = {}
    stringList = []
    for string in tree.find_all(string=re.compile(keyword)):
        parents_string = []
        for parent in string.find_parents():
            if parent.name == 'entry' and parent.name is not None and parent.get('name') != 'localhost.localdomain' and parent.get('name') != 'vsys1':
                parent.name = "entry[@name='" + parent.get('name') + "']"
            if parent.name != u'result' and parent.name != u'response' and parent.name != u'[document]':
                parents_string.append(parent.name)
        stringDict.update({parents_string[0] + "[text()='" + str(string) + "']": parents_string[1:][::-1]})
        for key, value in stringDict.items():
            xPath_string = ''
            for item in value:
                xPath_string = xPath_string + '/' + str(item)
            xPath_string = xPath_string + '/' + str(key)
            stringList.append(xPath_string)
    stringList = list(set(stringList[:]))
    stringList.sort()
    return stringDict, stringList


def main():
    print('\n')
    keyCheck = True
    while True:
        if keyCheck:  # Only prompt for address and credentials if first time
            fwip = getfwipfqdn()
            mainkey = getkey(fwip)
            keyCheck = False

        # Get the config from the Panorama/Firewall, and save it as a Beautiful Soup tree object
        fullurl = 'https://' + fwip + '/api/?type=op&cmd=<show><config><running></running></config></show>&key=' + mainkey
        r = requests.get(fullurl, verify=False)
        tree = BeautifulSoup(r.text, 'html.parser')

        # Prompt user to enter the keyword, for which to search the xml config
        while True:
            keyword = input('\n\nWhat keyword would you like to search for?  ')
            keyword_r = re.match(r"^(\s*\S+(.|\n)*)$", keyword)  # Check the entry for the proper format (must contain something other than just whitespace)
            if keyword_r:
                break
            else:
                time.sleep(1)
                print("\nThere was something wrong with your entry. Please try again...\n")

        print('\n\n')

        # Lists that will contain the finished xpaths with keyword matches on the tags, attributes, and strings respectively
        xPathDict_tag, xPathList_tags = tagSearch(tree, keyword)
        xPathDict_attr, xPathList_attrs = attrSearch(tree, keyword)
        xPathDict_string, xPathList_strings = stringSearch(tree, keyword)

        count = 1
        # Prints the xpaths where the keyword string matches on the attributes
        time.sleep(1)
        print('\nXpaths with keyword in tags:')
        if xPathList_tags == []:
            print('THERE ARE NO XPATHS THAT MATCH YOUR KEYWORD')
        else:
            for xpath in xPathList_tags:
                print(str(count) + ') ' + xpath)
                count += 1

        # Prints the xpaths where the keyword string matches on the attributes
        time.sleep(1)
        print('\nXpaths with keyword in attributes:')
        if xPathList_attrs == []:
            print('THERE ARE NO XPATHS THAT MATCH YOUR KEYWORD')
        else:
            for xpath in xPathList_attrs:
                print(str(count) + ') ' + xpath)
                count += 1

        # Prints the xpaths where the keyword string matches on the text
        time.sleep(1)
        print('\nXpaths with keyword in text:')
        if xPathList_strings == []:
            print('THERE ARE NO XPATHS THAT MATCH YOUR KEYWORD')
        else:
            for xpath in xPathList_strings:
                print(str(count) + ') ' + xpath)
                count += 1

        # Prompts the user with the ability to list the children of a selected xpath
        run = True
        another = True
        while run:
            seeChild = input('\n\n\nWould you like to see the children in an xpath? [Y/n]  ')
            if seeChild == 'Y' or seeChild == 'y' or seeChild == '':
                while another:
                    xpathChoice = input('\n\nChoose the corresponding number for the xpath: ')
                    xpathChoice_r = re.match(r'^\d*$', xpathChoice)
                    if xpathChoice_r:
                        xpathChoice = int(xpathChoice)
                        if xpathChoice < count:
                            print('')
                            run = False
                            r = requests.get(fullurl, verify=False)
                            treeET = ET.fromstring(r.text)
                            if xpathChoice <= len(xPathList_tags):  # If the user chooses a number in the tag list
                                childXpath = './result' + str(xPathList_tags[xpathChoice - 1])
                                childXpath = re.sub(r"\[text\(\)=(.|\n)*$", '', childXpath)
                                children = list(treeET.find(childXpath))
                                if children == []:
                                    print('THERE ARE NO CHILDREN FOR THE CHOSEN XPATH')
                                for element in children:
                                    if element.tag is not None:
                                        if element.get('name') is None:
                                            if element.text is None or bool(re.match(r"^\n\s+$", element.text)) is True:
                                                print(str(xPathList_tags[xpathChoice - 1]) + '/' + element.tag)
                                            else:
                                                print(str(xPathList_tags[xpathChoice - 1]) + '/' + element.tag + "[text()='" + element.text + "']")
                                        else:
                                            if element.text is None or bool(re.match(r"^\n\s+$", element.text)) is True:
                                                print(str(xPathList_tags[xpathChoice - 1]) + '/' + element.tag + "[@name='" + element.get('name') + "']")
                                            else:
                                                print(str(xPathList_tags[xpathChoice - 1]) + '/' + element.tag + "[@name='" + element.get('name') + "'][text()='" + element.text + "']")
                                    else:
                                        print('THERE ARE NO CHILDREN FOR THE CHOSEN XPATH')
                            elif xpathChoice <= len(xPathList_attrs) + len(xPathList_tags):  # If the user chooses a number in the attribute list
                                children = list(treeET.find('./result' + str(xPathList_attrs[xpathChoice - len(xPathList_tags) - 1])))
                                if children == []:
                                    print('THERE ARE NO CHILDREN FOR THE CHOSEN XPATH')
                                for element in children:
                                    if element.tag is not None:
                                        if element.get('name') is None:
                                            if element.text is None or bool(re.match(r"^\n\s+$", element.text)) is True:
                                                print(str(xPathList_attrs[xpathChoice - len(xPathList_tags) - 1]) + '/' + element.tag)
                                            else:
                                                print(str(xPathList_attrs[xpathChoice - len(xPathList_tags) - 1]) + '/' + element.tag + "[text()='" + element.text + "']")
                                        else:
                                            print(str(xPathList_attrs[xpathChoice - len(xPathList_tags) - 1]) + '/' + element.tag + "[@name='" + element.get('name') + "']")
                                    else:
                                        print('THERE ARE NO CHILDREN FOR THE CHOSEN XPATH')
                            else:  # If the user chooses a number in the strings list
                                childXpath = './result' + str(xPathList_strings[xpathChoice - (len(xPathList_tags) + len(xPathList_attrs)) - 1])
                                childXpath = re.sub(r"\[text\(\)=(.|\n)*$", '', childXpath)
                                children = list(treeET.find(childXpath))
                                if children == []:
                                    print('THERE ARE NO CHILDREN FOR THE CHOSEN XPATH')
                                for element in children:
                                    if element.tag is not None:
                                        if element.get('name') is None:
                                            if element.text is None or bool(re.match(r"^\n\s+$", element.text)) is True:
                                                print(str(xPathList_strings[xpathChoice - (len(xPathList_tags) + len(xPathList_attrs)) - 1]) + '/' + element.tag)
                                            else:
                                                print(str(xPathList_strings[xpathChoice - (len(xPathList_tags) + len(xPathList_attrs)) - 1]) + '/' + element.tag + "[text()='" + element.text + "']")
                                        else:
                                            if element.text is None or bool(re.match(r"^\n\s+$", element.text)) is True:
                                                print(str(xPathList_strings[xpathChoice - (len(xPathList_tags) + len(xPathList_attrs)) - 1]) + '/' + element.tag + "[@name='" + element.get('name') + "']")
                                            else:
                                                print(str(xPathList_strings[xpathChoice - (len(xPathList_tags) + len(xPathList_attrs)) - 1]) + '/' + element.tag + "[@name='" + element.get('name') + "'][text()='" + element.text + "']")
                                    else:
                                        print('THERE ARE NO CHILDREN FOR THE CHOSEN XPATH')
                            while True:
                                seeAnotherChild = input('\n\nWould you like to see the children of another xpath? [Y/n]  ')
                                if seeAnotherChild == 'Y' or seeAnotherChild == 'y' or seeAnotherChild == '':
                                    break
                                elif seeAnotherChild == 'N' or seeAnotherChild == 'n':
                                    another = False
                                    break
                                else:
                                    time.sleep(1)
                                    print("\n\nThat wasn't one of the options, try a 'y' or 'n' this time...")

                        else:
                            time.sleep(1)
                            print('\n\nThe number chosen was not one of the options listed, please try again...')
                    else:
                        time.sleep(1)
                        print('\n\nYou did not choose a number, please try again...')
            elif seeChild == 'N' or seeChild == 'n':
                break
            else:
                time.sleep(1)
                print("\n\nThat wasn't one of the options, try a 'y' or 'n' this time...")
        print('\n\n')

        while True:
            anotherKeyword = input('\n\n\nWould you like to search for another keyword? [Y/n]  ')
            if anotherKeyword == 'Y' or anotherKeyword == 'y' or anotherKeyword == '':
                print('\n')
                break
            elif anotherKeyword == 'N' or anotherKeyword == 'n':
                time.sleep(1)
                print('\n\nThen we are done here.\n\nHave a fantastic day!!!\n\n\n')
                exit()
            else:
                time.sleep(1)
                print("\n\nThat wasn't one of the options, try a 'y' or 'n' this time...")


if __name__ == '__main__':
    main()
