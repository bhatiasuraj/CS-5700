#!/usr/bin/python
from socket import *
import ssl, sys
host = 'cs5700sp16.ccs.neu.edu'
port = 27994

if ((len(sys.argv) == 4 and sys.argv[1] == '-s' and (sys.argv[2]).find('ccs.neu.edu') != -1) or (len(sys.argv) == 5
 and int(sys.argv[2]) == 27994 and (sys.argv[3]).find('ccs.neu.edu')!= -1)):

        clientsocket = socket(AF_INET, SOCK_STREAM)                                  #Conditions for creating SSL socket

        sslsock = ssl.wrap_socket(clientsocket, server_side=False, cert_reqs=ssl.CERT_NONE, ssl_version=ssl.PROTOCOL_SSLv23,
ca_certs=None, do_handshake_on_connect=True)

        if(len(sys.argv) == 4):
                message ="cs5700spring2016 HELLO "+ (sys.argv[3]) +"\n"              #Creating HELLO message to server with unique NEUID
                sslsock.connect((host, port))                                        #Binding SSL socket with specified host and port number
                sslsock.send(message)                                                #Sending HELLO message to the server
        else:
                message ="cs5700spring2016 HELLO "+ (sys.argv[4])+"\n"
                sslsock.connect((host, port))
                sslsock.send(message)

elif ((len(sys.argv) == 5 and sys.argv[1] == '-p' and int(sys.argv[2]) == 27993 and (sys.argv[3]).find('ccs.neu.edu')!= -1)
 or (len(sys.argv) == 3 and (sys.argv[1]).find('ccs.neu.edu')!= -1 and sys.argv[2] != "")):

        port = 27993
        sslsock = socket(AF_INET, SOCK_STREAM)

        if(len(sys.argv) == 5):
                message ="cs5700spring2016 HELLO "+ (sys.argv[4]) +"\n"
                sslsock.connect((host, port))                                        #Binding socket with specified host and port number
                sslsock.send(message)
        else:
                message ="cs5700spring2016 HELLO "+ (sys.argv[2])+"\n"
                sslsock.connect((host, port))
                sslsock.send(message)
else:
        print ("ERROR: Use format : ./client <-p port> <-s> [hostname] [NEU ID] ")   #Printing error message for improper command line input
        print ("Use format for hostname as ccs.neu.edu")
        print ("Use port number 27994 for SSL or else 27993")
        exit()


while True:

        status = sslsock.recv(256)                                                   #Receiving STATUS message from the server
        secret_flag = (status.split()[1])                                            #Extracting secret flag from the STATUS message
        flag =(status.split()[2])                                                    #Exiting loop when BYE message received
        if(flag=='BYE'):
                break
        num1=int(status.split()[2])                                                  #Extracting first number
        oper=status.split()[3]                                                       #Extracting mathematical number
        num2=int(status.split()[4])                                                  #Extracting second number

         if oper=='+':
                solution=num1 + num2
        elif oper=='-':
                solution=num1 - num2
        elif oper=='*':
                solution=num1 * num2
        elif oper=='/':
                solution=num1 / num2
        else:
                print("ERROR: Incorrect Operator")                                   #Print error message for incorrect mathematical operator
        s=str(solution)

        sol="cs5700spring2016 " +(s) +"\n"                                           #Creating SOLUTION message to send to the server
        sslsock.send(sol)                                                            #Sending SOLUTION to the server
print (secret_flag)                                                                  #Printing SECRET flag
sslsock.close()                                 
