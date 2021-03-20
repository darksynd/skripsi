import sys
import json
from collections import OrderedDict

line_width = 20
if (len(sys.argv) > 3):
    logFile = "Null"
    sessionFind = "Null"
    noArg = "Error"
elif (len(sys.argv) == 3):
    logFile = sys.argv[1]
    sessionFind = sys.argv[2]
    noArg = "Null"
elif (len(sys.argv) == 2):
    logFile = sys.argv[1]
    sessionFind = "Null"
    noArg = "Null"
elif (len(sys.argv) == 1):
    logFile = "Null"
    sessionFind = "Null"
    noArg = "Error"


if (noArg == "Error" or logFile == "Null"): #Error Message
    print "Error! You can not run the script with this command"
    print "Please use command -h or --h to open help"
    print "So, you can learn how to run the script"
elif (logFile == "-h" or logFile == "-help" or logFile == "--h" or logFile == "--help"): #help
    print "\nAnalyze Pattern Attack Using Mitre Att&ck as a Guide\n"
    print "You can run the script by using 2 method:\n"
    print "--First Method: It will Analyze your Cowrie Log Json File line per"
    print "\t\tline from top to bottom and print all of the output\n"
    print "\t skripsi.py [String 1]\n"
    print "\t  [String 1]\t\tCowrie Log Json File"
    print "\t\t\t  \t>> You can get your Cowrie Log Json File from"
    print "\t\t\t  \tCowrie/var/log/Cowrie by default\n"
    print "Example: skripsi.py .\cowrie.json.2020-11-10\n\n"
    print "--Second Method: It will Analyze your Cowrie Log Json File line per"
    print "\t\t line from top to bottom and print all of the "
    print "\t\t output that filtered by the session that you search\n"
    print "\t skripsi.py [String 1] [String 2]\n"
    print "\t  [String 1]\t\tCowrie Log Json File"
    print "\t\t\t  \t>> You can get your Cowrie Log Json File from"
    print "\t\t\t  \tCowrie/var/log/Cowrie by default\n"
    print "\t  [String 2]\t\tThe first 12 strings of the Session that you want to search"
    print "\t\t\t  \t>> You can copy the session that you want to search from"
    print "\t\t\t  \tCowrie Log File or Cowrie Log Json File\n"
    print "Example: skripsi.py .\cowrie.json.2020-11-10 4ea2ca4eaf92\n"
elif (sessionFind == "Null" and logFile != "-h" or logFile != "-help" or logFile != "--h" or logFile != "--help"): #No session, full Log
    print sessionFind
    print "ini gak ada session"
    data = []
    resultPerLine = { #dictionary untuk result per line
        "actionType": "",
        "session": "",
        "source_ip": "",
        "command":"",
        "mitre":"",
        "timestamp":""
    } 
    f = open(logFile, "r")

    for line in f:
        data.append(json.loads(line))
    print ""
    print "        Time Stamp\t\t        Action Type\t\t     Session\t     IP\t\t        Command List\t\t          List Mittre Attack"
    print "======================================================================================================================================================================="

    for i in range(0, len(data)):
        resultPerLine["actionType"] = ""
        if (data[i]["eventid"] == "cowrie.session.connect"):
            resultPerLine["actionType"] = "Connect to SSH"
            resultPerLine["command"] = "-"
        elif (data[i]["eventid"] == "cowrie.session.closed"):
            resultPerLine["actionType"] = "Disconnect from SSH"
            resultPerLine["command"] = "-"
            if(data[i-1]["eventid"] == "cowrie.session.connect" or data[i-2]["eventid"] == "cowrie.session.connect" or data[i-3]["eventid"] == "cowrie.session.connect" or data[i-5]["eventid"] == "cowrie.session.connect"):
                resultPerLine["mitre"] = "(Reconisance) Test Connection"
        elif (data[i]["eventid"] == "cowrie.login.success"):
            resultPerLine["actionType"] = "Login attemp as {}@{} success".format(data[i]["username"],data[i]["password"])
            resultPerLine["command"] = "-"
        elif (data[i]["eventid"] == "cowrie.login.failed"):
            resultPerLine["actionType"] = "Login attemp as {}@{} failed".format(data[i]["username"],data[i]["password"])
            resultPerLine["command"] = "-"
        elif (data[i]["eventid"] == "cowrie.command.failed"):
            resultPerLine["actionType"] = "Command failed"
            resultPerLine["command"] = data[i]["message"]
        elif (data[i]["eventid"] == "cowrie.log.closed"):
            resultPerLine["actionType"] = "Closing TTY Log for this Session"
        elif (data[i]["eventid"] == "cowrie.command.input"):
            resultPerLine["actionType"] = "Run a command"
            resultPerLine["command"] = data[i]["input"]


        resultPerLine["session"] = data[i]["session"]
        resultPerLine["source_ip"] = data[i]["src_ip"]
        resultPerLine["timestamp"] = data[i]["timestamp"]
        print "{:25}  {:35}  {:10}  {:5}  {:25}            {:20}".format(resultPerLine["timestamp"], resultPerLine["actionType"], resultPerLine["session"], resultPerLine["source_ip"], resultPerLine["command"], resultPerLine["mitre"]).ljust(line_width)
        if (data[i]["eventid"] == "cowrie.session.closed"):
            print "-----------------------------------------------------------------------------------------------------------------------------------------------------------------------"
        resultPerLine = { #dictionary untuk result per line
        "actionType": "",
        "session": "",
        "source_ip": "",
        "command":"",
        "mitre":"",
        "timestamp":""
        }  

elif (sessionFind != "Null" and logFile != "-h" or logFile != "-help" or logFile != "--h" or logFile != "--help"): #1 session only
    print "ini ada sesi"
    data = []
    logFile = sys.argv[1]
    resultPerLine = { #dictionary untuk result per line
        "actionType": "",
        "session": "",
        "source_ip": "",
        "command":"",
        "mitre":"",
        "timestamp":""
    } 
    f = open(logFile, "r")

    for line in f:
        data.append(json.loads(line))
    print ""
    print "        Time Stamp\t\t        Action Type\t\t     Session\t     IP\t\t        Command List\t\t          List Mittre Attack"
    print "======================================================================================================================================================================="

    for i in range(0, len(data)):
        resultPerLine["actionType"] = ""
        if (data[i]["eventid"] == "cowrie.session.connect"):
            resultPerLine["actionType"] = "Connect to SSH"
            resultPerLine["command"] = "-"
        elif (data[i]["eventid"] == "cowrie.session.closed"):
            resultPerLine["actionType"] = "Disconnect from SSH"
            resultPerLine["command"] = "-"
            if(data[i-1]["eventid"] == "cowrie.session.connect" or data[i-2]["eventid"] == "cowrie.session.connect" or data[i-3]["eventid"] == "cowrie.session.connect" or data[i-5]["eventid"] == "cowrie.session.connect"):
                resultPerLine["mitre"] = "(Reconisance) Test Connection"
        elif (data[i]["eventid"] == "cowrie.login.success"):
            resultPerLine["actionType"] = "Success Login as {}@{}".format(data[i]["username"],data[i]["password"])
            resultPerLine["command"] = "-"
        elif (data[i]["eventid"] == "cowrie.command.input"):
            resultPerLine["actionType"] = "Run a command"
            resultPerLine["command"] = data[i]["input"]
        elif (data[i]["eventid"] == "cowrie.command.failed"):
            resultPerLine["actionType"] = "Command failed"
            resultPerLine["command"] = data[i]["message"]
        elif (data[i]["eventid"] == "cowrie.log.closed"):
            resultPerLine["actionType"] = "Closing TTY Log for this Session"

        #resultPerLine.move_to_end("session")
        #resultPerLine.move_to_end("source_ip")
        resultPerLine["session"] = data[i]["session"]
        resultPerLine["source_ip"] = data[i]["src_ip"]
        resultPerLine["timestamp"] = data[i]["timestamp"]
        print "{:25}  {:35}  {:10}  {:5}  {:25}            {:20}".format(resultPerLine["timestamp"], resultPerLine["actionType"], resultPerLine["session"], resultPerLine["source_ip"], resultPerLine["command"], resultPerLine["mitre"])
        if (data[i]["eventid"] == "cowrie.session.closed"):
            print "-----------------------------------------------------------------------------------------------------------------------------------------------------------------------"
        resultPerLine = { #dictionary untuk result per line
        "actionType": "",
        "session": "",
        "source_ip": "",
        "command":"",
        "mitre":"",
        "timestamp":""
        } 