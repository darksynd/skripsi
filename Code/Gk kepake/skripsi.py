import sys
import json
import csv
from os import path
from datetime import date
from collections import OrderedDict


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
    print "Example: skripsi.py ./cowrie.json.2020-11-10\n\n"
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
    print "Example: skripsi.py ./cowrie.json.2020-11-10 4ea2ca4eaf92\n\n"
    print "The Script will give output in terminal and generate a CSV File"
    print "The CSV File name template is \"CowrieLogAnalyzeResult yyyy-mm-dd\""
    print "\nPlease Note that, CSV File will be appended with the output if CSV file name already exist"
    print "in the current directory when run the script. You can prevent it by move the existing"
    print "file to another directory/folder, remove the existing file, or rename the existing file"
elif (logFile != "-h" or logFile != "-help" or logFile != "--h" or logFile != "--help"): #analyze Log
    if(sessionFind == "Null"): #no session
        data = []
        mitreList = []
        mitre = ""
        resultPerLine = { #dictionary untuk result per line
            "actionType": "",
            "session": "",
            "source_ip": "",
            "command":"",
            "timestamp":""
        }
        
        f = open(logFile, "r")

        for line in f:
            data.append(json.loads(line))

        print ""
        print "        Time Stamp\t\t        Action Type\t\t       Session\t            IP\t\t        Command List\t\t          List Mittre Attack"
        print "======================================================================================================================================================================="

        for i in range(0, len(data)):

            resultPerLine["timestamp"] = data[i]["timestamp"]
            resultPerLine["session"] = data[i]["session"]
            resultPerLine["source_ip"] = data[i]["src_ip"]
            resultPerLine["actionType"] = ""

            if (data[i]["eventid"] == "cowrie.session.connect"): #14
                resultPerLine["actionType"] = "New Connection to SSH"
                resultPerLine["command"] = "-"
            elif (data[i]["eventid"] == "cowrie.session.closed"): #13
                resultPerLine["actionType"] = "Connection lost from SSH" 
                resultPerLine["command"] = "-"
                if(data[i-1]["eventid"] == "cowrie.session.connect" and resultPerLine["session"] == data[i-1]["session"]):
                    mitreList.append("T444 (Reconisance) Test Connection")
                elif (data[i-2]["eventid"] == "cowrie.session.connect" and resultPerLine["session"] == data[i-2]["session"]):
                    mitreList.append("T444 (Reconisance) Test Connection")
                elif (data[i-3]["eventid"] == "cowrie.session.connect" and resultPerLine["session"] == data[i-3]["session"]):
                    mitreList.append("T444 (Reconisance) Test Connection")
                elif (data[i-4]["eventid"] == "cowrie.session.connect" and resultPerLine["session"] == data[i-4]["session"]):
                    mitreList.append("T444 (Reconisance) Test Connection")
            elif (data[i]["eventid"] == "cowrie.login.success"): #12
                resultPerLine["actionType"] = "Login attemp as {}@{} success".format(data[i]["username"],data[i]["password"])
                resultPerLine["command"] = "-"
            elif (data[i]["eventid"] == "cowrie.login.failed"): #11
                resultPerLine["actionType"] = "Login attemp as {}@{} failed".format(data[i]["username"],data[i]["password"])
                resultPerLine["command"] = "-"
            elif (data[i]["eventid"] == "cowrie.command.failed"): #4
                resultPerLine["actionType"] = "Command failed to run"
                resultPerLine["command"] = data[i]["message"]
            elif (data[i]["eventid"] == "cowrie.command.success"): #6
                resultPerLine["actionType"] = "Command succeed to run"
                resultPerLine["command"] = data[i]["message"]
            elif (data[i]["eventid"] == "cowrie.log.closed"): #9
                resultPerLine["actionType"] = "Closing TTY Log (Input Log) for this Session"
                resultPerLine["command"] = "-"
            elif (data[i]["eventid"] == "cowrie.log.open"): #10
                resultPerLine["actionType"] = "Opening TTY Log (Input Log) for this Session"
                resultPerLine["command"] = "-"
            elif (data[i]["eventid"] == "cowrie.client.fingerprint"): #1
                resultPerLine["actionType"] = "Cowrie save the fingerprint of the SSH connector as {}".format(data[i]["fingerprint"])
                resultPerLine["command"] = "-"
            elif (data[i]["eventid"] == "cowrie.client.kex"): #1
                resultPerLine["actionType"] = "Cowrie save the SSH client hassh fingerprint as {}".format(data[i]["hassh"])
                resultPerLine["command"] = "-"
            elif (data[i]["eventid"] == "cowrie.client.size"): #2
                resultPerLine["actionType"] = "Cowrie save the size of terminal session as height: {} and width {}".format(data[i]["height"], data[i]["width"])
                resultPerLine["command"] = "-"
            elif (data[i]["eventid"] == "cowrie.client.version"): #3 BLM FIX
                resultPerLine["actionType"] = "Version"
                resultPerLine["command"] = "-"
            elif (data[i]["eventid"] == "cowrie.direct-tcpip.data"): #7
                resultPerLine["actionType"] = data[i]["message"]
                resultPerLine["command"] = "-"
            elif (data[i]["eventid"] == "cowrie.direct-tcpip.request"): #8
                resultPerLine["actionType"] = data[i]["message"]
                resultPerLine["command"] = "-"
            elif (data[i]["eventid"] == "cowrie.session.file_download"): #15
                resultPerLine["actionType"] = data[i]["message"]
                resultPerLine["command"] = "-"
            elif (data[i]["eventid"] == "cowrie.session.file_upload"): #16
                resultPerLine["actionType"] = data[i]["message"]
                resultPerLine["command"] = "-"
            elif (data[i]["eventid"] == "cowrie.session.input"): #17 BLM FIX
                resultPerLine["actionType"] = data[i]["message"]
                resultPerLine["command"] = data[i]["input"]
            elif (data[i]["eventid"] == "cowrie.client.var"): #18 BLM FIX
                resultPerLine["actionType"] = data[i]["message"]
                resultPerLine["command"] = "-"
            elif (data[i]["eventid"] == "cowrie.session.params"): #BLM FIX
                resultPerLine["actionType"] = "CPU/OS architecture emulated by cowrie saved as {}".format(data[i]["arch"])
                resultPerLine["command"] = "-"

            elif (data[i]["eventid"] == "cowrie.command.input"): #5
                resultPerLine["actionType"] = "Run a command"
                resultPerLine["command"] = data[i]["input"]
                if("scp" in resultPerLine["command"] or "wget" in resultPerLine["command"] or "tftp" in resultPerLine["command"]):
                    mitreList.append("T123 (Exploitation) ingress file injection")
                if("rm" in resultPerLine["command"]):
                    mitreList.append("T212 (Destroy) Destroy the system")
                if("netstat" in resultPerLine["command"]):
                    mitreList.append("T212 (abc) abc")
                if("dd" in resultPerLine["command"]):
                    mitreList.append("T212 (abc) abc")
                if("shell" in resultPerLine["command"] or "sh" in resultPerLine["command"]):
                    mitreList.append("T212 (abc) abc")
                if("system" in resultPerLine["command"]):
                    mitreList.append("T212 (abc) abc")
                if("curl" in resultPerLine["command"]):
                    mitreList.append("T212 (abc) abc")
                
                
            for j in range(len(mitreList)):
                mitre = mitreList[j] + " | " + mitre
            
            with open("CowrieLogAnalyzeResult " + str(date.today()) + ".csv", 'ab') as csvfile:
                writer = csv.writer(csvfile)
                if(i == 0):
                    writer.writerow(["Log File Name:", logFile])
                    writer.writerow(["Time Stamp", "Action Type", "Session", "IP", "Command List", "List Mitre Attack"])
                    writer.writerow([resultPerLine["timestamp"], resultPerLine["actionType"], resultPerLine["session"], resultPerLine["source_ip"], str(resultPerLine["command"]), mitre])
                else:
                    writer.writerow([resultPerLine["timestamp"], resultPerLine["actionType"], resultPerLine["session"], resultPerLine["source_ip"], str(resultPerLine["command"]), mitre])
            
            
            Akhir = "{:25}  {:38}  {:16}  {:16}  {:25}            {:20}".format(resultPerLine["timestamp"], resultPerLine["actionType"], resultPerLine["session"], resultPerLine["source_ip"], resultPerLine["command"], mitre)
            print Akhir

            if (data[i]["eventid"] == "cowrie.session.closed"):
                print "-----------------------------------------------------------------------------------------------------------------------------------------------------------------------"

            resultPerLine = { #dictionary untuk result per line
            "actionType": "",
            "session": "",
            "source_ip": "",
            "command":"",
            "timestamp":""
            }  
            mitreList = []
            mitre = ""
    
    elif(sessionFind != "Null"): #check 1 session only
        print "check 1 session only"