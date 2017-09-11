#!/usr/bin/python2.7

import socket
import sys
import array
from bs4 import BeautifulSoup

# Check if only two paramters are passed and extract them, else print error.
if ( len( sys.argv ) ==  3):
        username = sys.argv[1]
        password = sys.argv[2]
else:
        print ("Illegal number of arguments passed, please try again.")
        sys.exit()

host = ('cs5700sp16.ccs.neu.edu')
port = 80

# Function for creating sockets, sending and receiving data via sockets.
def createsocket(host, port, message):
    crawl_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ip_address = str(socket.gethostbyname( host ))
    crawl_socket.connect((ip_address, port))

    # Error handling if socket not created.
    try:
        crawl_socket.sendall(message)
    except:
        print 'Socket not created, try again.'
        sys.exit()
    first_get = crawl_socket.recv(4096)
    return first_get

# Function for HTTP GET message to load root Fakebook page.
def firstGETmessage( host ):

    # Create GET header.
    get_message = 'GET /accounts/login/?next=/fakebook/ / HTTP/1.1Host:'+host+'\r\n\r\n'
    first_get = ( createsocket( host, port, get_message ))
    global csrftoken, sessionid

    # Extract csrftoken and session from GET response to add them to POST header
    csrftoken = first_get.split()[27][10:-1]
    sessionid = first_get.split()[35][10:-1]

    return (csrftoken, sessionid)

csrftoken, sessionid = firstGETmessage(host)
contentlength = ('109')

#Function for HTTP POST message to login into Fakebook:
def POSTmessage( username, password, host ):
 # Create POST header.
    post_message = ('POST /accounts/login/ / HTTP/1.1\r\n'
                'Host: cs5700sp16.ccs.neu.edu\r\n'
                'Connection: keep-alive\r\n'
                'Content-length: ' + contentlength +'\r\n'
                'Origin: http://'+host+'\r\n'
                'User-Agent: User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2486.0 Safari/537.36 Edge/13.1058$
                'Content-type: application/x-www-form-urlencoded\r\n'
                'Accept-Encoding: gzip, deflate\r\n'
                'Cookie: csrftoken='+csrftoken+'; sessionid= '+sessionid+'\r\r\n\n')

    # Add POST body to header.
    post_message += ('username='+username+'&password='+password+'&csrfmiddlewaretoken='+csrftoken+'&next=/fakebook/\r\n\r\n')

    post_response = createsocket(host, port, post_message)
    post_status = post_response.split()[1]

    # Handle incorrect login credential.
    try:
        # New session id to crawl Fakebook pages
        session_id = (post_response.split()[27])[10:-1]
        home_page = (post_response.split()[42][0:39])
        return (session_id, home_page)
 except:
        post_status != '302'
        print ('Incorrect credentials, please try again.')
        sys.exit()


session_id, home_page = POSTmessage(username, password, host)

# Created arrays for adding to be visited and already visited URLs
urls_to_visit = [home_page]
urls_visited = [home_page]

#Initialize number of secret flags
no_of_secret_flags = 0


# Function to create HTTP GET message
def GETwithCookie():
 # Create HTTP GET header
    get_fakebook = 'GET '+str(urls_to_visit[0])+' / HTTP/1.1\r\nHost:'+host+'\r\nCookie: csrftoken='+csrftoken+'; sessionid='+session_id+'\r\nConnection:keep-alive\r\n$
    crawl_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ip_address = socket.gethostbyname(host)
    crawl_socket.connect((ip_address, port))
    try:
        crawl_socket.send(get_fakebook)
    except:
        print 'Socket not created, try again.'
        sys.exit()

    global get_with_cookie
    get_with_cookie = crawl_socket.recv(8192)

    # Extracting HTTP status code to check for errors
    global HTTP_status
    HTTP_status = get_with_cookie.split(' ')[1]
    return get_with_cookie
# Loop to parse for URLs, secret flags and error handling
while( no_of_secret_flags <= 4):
    GETwithCookie()

    # Handles 500 Internal Server Error
    if HTTP_status == '500':
        while( HTTP_status != '200' ):
            get_fakebook = GETwithCookie()

    # Handles 301 Redirection
    if HTTP_status == '301':
        redirected_url = post_response.split()[8:]
        urls_to_visit[0] = redirected_url
        GETwithCookie()

    # Handles Not Found, Bad Request and Forbidden Error
    if HTTP_status == '404' or HTTP_status == '400' or HTTP_status == '403':
        urls_to_visit.pop(0)
 # Parses HTML pages and extracts 5 secret flags with specific HTML attributes
    flag_finder = BeautifulSoup(get_with_cookie, "html.parser")
    for tag in flag_finder.find_all('h2', attrs = {"class": "secret_flag"}):
        print flag_finder.h2.text[6:70]
        no_of_secret_flags = no_of_secret_flags + 1
        break

    # Parses HTML pages and extracts URLs
    url_parse = BeautifulSoup(get_with_cookie, "html.parser")
    for tag in url_parse.findAll('a', href=True):
        url = str(tag['href'])

        # Checks condition if url is visited or not and is a part of Fakebook
        if(url not in urls_visited and url.find('/fakebook/')!=-1):
            urls_to_visit.append(tag['href'])
            urls_visited.append(tag['href'])

    # Removes URL that is visited from the unvisited URL array
    urls_to_visit.pop(0)


