#!C:/Python27/python.exe
import cgi
import sys
import json
import csv
import time
from os import path
from datetime import date
from collections import OrderedDict


formData = cgi.FieldStorage()

fileLog = formData.getvalue('log')

ui = { #dictionary untuk result per line
    "session": "",
    "ip": "",
    "command": "",
    "start": "",
    "finish":"",
    "mitre":""
}

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
checkFile = 0
t = time.localtime()
current_time = time.strftime("%H.%M.%S", t)

resultName = "./result/CowrieLogAnalyzeResult " + str(date.today()) + " " + current_time + ".csv"

location = "./logs/" + fileLog

f = open(location, "r")

with open(location) as fp:
   line = fp.readline()
   while line:
       if("eventId" not in line.strip() and "session" not in line.strip() and "timestamp" not in line.strip() and "src_ip" not in line.strip()):
           checkFile += 1
       line = fp.readline()
       if(checkFile == 10):
           error = "The file that you submitted is not Cowrie Log with JSON format<br>You can get Cowrie Log with JSON format from your log folder, the default path is cowrie/var/log/cowrie"
           print('Content-type:text/html\n\n')
           redirectURL = "http://localhost:8080/index.php?error=" + error
           print('<html>')
           print('  <head>')
           print('    <meta http-equiv="refresh" content="0;url='+str(redirectURL)+'" />') 
           print('  </head>')
           print('</html>')

for line in f:
    data.append(json.loads(line))



for i in range(0, len(data)):

    resultPerLine["timestamp"] = data[i]["timestamp"]
    resultPerLine["session"] = data[i]["session"]
    resultPerLine["source_ip"] = data[i]["src_ip"]
    resultPerLine["actionType"] = ""
    resultPerLine["command"] = "-"

    if (data[i]["eventid"] == "cowrie.session.connect"): #14
        resultPerLine["actionType"] = "New Connection to SSH"
    elif (data[i]["eventid"] == "cowrie.session.closed"): #13
        resultPerLine["actionType"] = "Connection lost from SSH" 
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
    elif (data[i]["eventid"] == "cowrie.login.failed"): #11
        resultPerLine["actionType"] = "Login attemp as {}@{} failed".format(data[i]["username"],data[i]["password"])
    elif (data[i]["eventid"] == "cowrie.command.failed"): #4
        resultPerLine["actionType"] = "Command failed to run"
        resultPerLine["command"] = data[i]["message"]
    elif (data[i]["eventid"] == "cowrie.command.success"): #6
        resultPerLine["actionType"] = "Command succeed to run"
        resultPerLine["command"] = data[i]["message"]
    elif (data[i]["eventid"] == "cowrie.log.closed"): #9
        resultPerLine["actionType"] = "Closing TTY Log (Input Log) for this Session"
    elif (data[i]["eventid"] == "cowrie.log.open"): #10
        resultPerLine["actionType"] = "Opening TTY Log (Input Log) for this Session"
    elif (data[i]["eventid"] == "cowrie.client.fingerprint"): #1
        resultPerLine["actionType"] = "Cowrie save the fingerprint of the SSH connector as {}".format(data[i]["fingerprint"])
    elif (data[i]["eventid"] == "cowrie.client.kex"): #
        resultPerLine["actionType"] = "Cowrie save the SSH client hassh fingerprint as {}".format(data[i]["hassh"])
    elif (data[i]["eventid"] == "cowrie.client.size"): #2
        resultPerLine["actionType"] = "Cowrie save the size of terminal session as height: {} and width {}".format(data[i]["height"], data[i]["width"])
    elif (data[i]["eventid"] == "cowrie.client.version"): #3 BLM FIX
        resultPerLine["actionType"] = "Version"
    elif (data[i]["eventid"] == "cowrie.direct-tcpip.data"): #7
        resultPerLine["actionType"] = data[i]["message"]
    elif (data[i]["eventid"] == "cowrie.direct-tcpip.request"): #8
        resultPerLine["actionType"] = data[i]["message"]
    elif (data[i]["eventid"] == "cowrie.session.file_download"): #15
        resultPerLine["actionType"] = data[i]["message"]
    elif (data[i]["eventid"] == "cowrie.session.file_upload"): #16
        resultPerLine["actionType"] = "File named {} uploaded to {} in SSH".format(data[i]["filename"], data[i]["outfile"])
    elif (data[i]["eventid"] == "cowrie.session.input"): #17 BLM FIX
        resultPerLine["actionType"] = data[i]["message"]
        resultPerLine["command"] = data[i]["input"]
    elif (data[i]["eventid"] == "cowrie.client.var"): #18 BLM FIX
        resultPerLine["actionType"] = data[i]["message"]
    elif (data[i]["eventid"] == "cowrie.session.params"): #BLM FIX
        resultPerLine["actionType"] = "CPU/OS architecture emulated by cowrie saved as {}".format(data[i]["arch"])

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

    with open(resultName, 'ab') as csvfile:
        writer = csv.writer(csvfile)
        if(i == 0):
            writer.writerow(["Log File Name:", fileLog])
            writer.writerow(["Time Stamp", "Action Type", "Session", "IP", "Command List", "List Mitre Attack"])
            writer.writerow([resultPerLine["timestamp"], resultPerLine["actionType"], resultPerLine["session"], resultPerLine["source_ip"], str(resultPerLine["command"]), mitre])
        else:
            writer.writerow([resultPerLine["timestamp"], resultPerLine["actionType"], resultPerLine["session"], resultPerLine["source_ip"], str(resultPerLine["command"]), mitre])

    resultPerLine = { #dictionary untuk result per line
    "actionType": "",
    "session": "",
    "source_ip": "",
    "command":"",
    "timestamp":""
    }  
    mitreList = []
    mitre = ""

print('Content-type:text/html\n\n')
redirectURL = "http://localhost:8080/downloadResult.php?log=" + fileLog + "&result=" + resultName
print('<html>')
print('  <head>')
print('    <meta http-equiv="refresh" content="0;url='+str(redirectURL)+'" />')
print('  </head>')
print('</html>')