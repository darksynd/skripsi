#!C:\Python27\python.exe
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

T1595 = 0
T1059 = 0
T1559 = 0
T1569 = 0
T1098 = 0
T1547 = 0
T1554 = 0
T1136 = 0
T1543 = 0
T1037 = 0
T1053 = 0
T1564 = 0
T1070 = 0
T1110 = 0
T1555 = 0
T1087 = 0
T1083 = 0
T1135 = 0
T1040 = 0
T1201 = 0
T1069 = 0
T1057 = 0
T1078 = 0
T1018 = 0
T1518 = 0
T1082 = 0
T1016 = 0
T1049 = 0
T1033 = 0
T1007 = 0
T1570 = 0
T1021 = 0
T1072 = 0
T1560 = 0
T1115 = 0
T1005 = 0
T1105 = 0
T1567 = 0
T1531 = 0
T1485 = 0
T1486 = 0
T1565 = 0
T1561 = 0
T1489 = 0
T1529 = 0
T1222 = 0


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
        if(data[i-1]["eventid"] == "cowrie.session.connect" and resultPerLine["source_ip"] == data[i-1]["src_ip"]):
            mitreList.append("T1595 (Reconnaissance) Active Scanning")
            T1595 = T1595 + 1
        elif (data[i-2]["eventid"] == "cowrie.session.connect" and resultPerLine["source_ip"] == data[i-2]["src_ip"]):
            mitreList.append("T1595 (Reconnaissance) Active Scanning")
            T1595 = T1595 + 1
        elif (data[i-3]["eventid"] == "cowrie.session.connect" and resultPerLine["source_ip"] == data[i-3]["src_ip"]):
            mitreList.append("T1595 (Reconnaissance) Active Scanning")
            T1595 = T1595 + 1
        elif (data[i-4]["eventid"] == "cowrie.session.connect" and resultPerLine["source_ip"] == data[i-4]["src_ip"]):
            mitreList.append("T1595 (Reconnaissance) Active Scanning")
            T1595 = T1595 + 1
    elif (data[i]["eventid"] == "cowrie.login.success"): #12
        resultPerLine["actionType"] = "Login attemp as {}@{} success".format(data[i]["username"],data[i]["password"])
        mitreList.append("T1021 (Lateral Movement) Remote Services")
        T1021 = T1021 + 1
        if(data[i-1]["eventid"] == "cowrie.login.success" or data[i-1]["eventid"] == "cowrie.login.failed" and resultPerLine["source_ip"] == data[i-1]["src_ip"]):
            mitreList.append("T1110 (Credential Access) Brute Force")
            T1110 = T1110 + 1
        elif (data[i-2]["eventid"] == "cowrie.login.success" or data[i-2]["eventid"] == "cowrie.login.failed" and resultPerLine["source_ip"] == data[i-2]["src_ip"]):
            mitreList.append("T1110 (Credential Access) Brute Force")
            T1110 = T1110 + 1
        elif (data[i-3]["eventid"] == "cowrie.login.success" or data[i-3]["eventid"] == "cowrie.login.failed" and resultPerLine["source_ip"] == data[i-3]["src_ip"]):
            mitreList.append("T1110 (Credential Access) Brute Force")
            T1110 = T1110 + 1
        elif (data[i-4]["eventid"] == "cowrie.login.success" or data[i-4]["eventid"] == "cowrie.login.failed" and resultPerLine["source_ip"] == data[i-4]["src_ip"]):
            mitreList.append("T1110 (Credential Access) Brute Force")
            T1110 = T1110 + 1
    elif (data[i]["eventid"] == "cowrie.login.failed"): #11
        resultPerLine["actionType"] = "Login attemp as {}@{} failed".format(data[i]["username"],data[i]["password"])
        if(data[i-1]["eventid"] == "cowrie.login.failed" or data[i-1]["eventid"] == "cowrie.login.success" and resultPerLine["source_ip"] == data[i-1]["src_ip"]):
            mitreList.append("T1110 (Credential Access) Brute Force")
            T1110 = T1110 + 1
        elif (data[i-2]["eventid"] == "cowrie.login.failed" or data[i-2]["eventid"] == "cowrie.login.success" and resultPerLine["source_ip"] == data[i-2]["src_ip"]):
            mitreList.append("T1110 (Credential Access) Brute Force")
            T1110 = T1110 + 1
        elif (data[i-3]["eventid"] == "cowrie.login.failed" or data[i-3]["eventid"] == "cowrie.login.success" and resultPerLine["source_ip"] == data[i-3]["src_ip"]):
            mitreList.append("T1110 (Credential Access) Brute Force")
            T1110 = T1110 + 1
        elif (data[i-4]["eventid"] == "cowrie.login.failed" or data[i-4]["eventid"] == "cowrie.login.success" and resultPerLine["source_ip"] == data[i-4]["src_ip"]):
            mitreList.append("T1110 (Credential Access) Brute Force")
            T1110 = T1110 + 1
    elif (data[i]["eventid"] == "cowrie.command.failed"): #4
        resultPerLine["actionType"] = "Command failed to run"
        resultPerLine["command"] = data[i]["message"]
    elif (data[i]["eventid"] == "cowrie.log.closed"): #9
        resultPerLine["actionType"] = "Closing TTY Log (Input Log) for this Session"
    elif (data[i]["eventid"] == "cowrie.log.open"): #10
        resultPerLine["actionType"] = "Opening TTY Log (Input Log) for this Session"
    elif (data[i]["eventid"] == "cowrie.client.fingerprint"): #1
        resultPerLine["actionType"] = "Cowrie save the fingerprint of the SSH connector as {}".format(data[i]["fingerprint"])
    elif (data[i]["eventid"] == "cowrie.client.kex"): #20
        resultPerLine["actionType"] = "Cowrie save the SSH client hassh fingerprint as {}".format(data[i]["hassh"])
    elif (data[i]["eventid"] == "cowrie.client.size"): #2
        resultPerLine["actionType"] = "Cowrie save the size of terminal session as height: {} and width {}".format(data[i]["height"], data[i]["width"])
    elif (data[i]["eventid"] == "cowrie.client.version"): #3 
        resultPerLine["actionType"] = "Cowrie save the version of SSH Client as {}".format(data[i]["version"])
    elif (data[i]["eventid"] == "cowrie.direct-tcpip.data"): #7
        resultPerLine["actionType"] = data[i]["message"]
    elif (data[i]["eventid"] == "cowrie.direct-tcpip.request"): #8
        resultPerLine["actionType"] = data[i]["message"]
    elif (data[i]["eventid"] == "cowrie.session.file_download"): #15
        resultPerLine["actionType"] = data[i]["message"]
    elif (data[i]["eventid"] == "cowrie.session.file_upload"): #16
        resultPerLine["actionType"] = "File named {} uploaded to {} in SSH".format(data[i]["filename"], data[i]["outfile"])
    elif (data[i]["eventid"] == "cowrie.session.input"): #17 
        resultPerLine["actionType"] = data[i]["message"]
        resultPerLine["command"] = data[i]["input"]
    elif (data[i]["eventid"] == "cowrie.client.var"): #18 
        resultPerLine["actionType"] = data[i]["message"]
    elif (data[i]["eventid"] == "cowrie.session.params"): #19 
        resultPerLine["actionType"] = "CPU/OS architecture emulated by cowrie saved as {}".format(data[i]["arch"])
    elif (data[i]["eventid"] == "cowrie.command.success"): #6
        resultPerLine["actionType"] = "Command succeed to run"
    elif (data[i]["eventid"] == "cowrie.command.input"): #5
        resultPerLine["actionType"] = "Run a command"
        resultPerLine["command"] = data[i]["input"]

        if("bash" in resultPerLine["command"] or "shell" in resultPerLine["command"] or "perl" in resultPerLine["command"] or ".js" in resultPerLine["command"] or ".py" in resultPerLine["command"] or ".sh" in resultPerLine["command"] or resultPerLine["command"] == "sh" or "python" in resultPerLine["command"]):
            mitreList.append("T1059 (Execution) Command and Scripting Interpreter")
            T1059 = T1059 + 1
        if("ipcs" in resultPerLine["command"] or "/etc/sysctl.conf" in resultPerLine["command"] or "nano /etc/sysctl.conf" in resultPerLine["command"] or "vim /etc/sysctl.conf" in resultPerLine["command"] or "cat /etc/sysctl.conf" in resultPerLine["command"] or "vi /etc/sysctl.conf" in resultPerLine["command"] or "less /etc/sysctl.conf" in resultPerLine["command"]):
            mitreList.append("T1559 (Execution) Inter-Process Communication")
            T1559 = T1559 + 1
        if("shell" in resultPerLine["command"] or "wget" in resultPerLine["command"] or "cp " in resultPerLine["command"] or resultPerLine["command"] == "sh" or "nc" in resultPerLine["command"]):
            mitreList.append("T1072 (Execution) Software Deployment Tools")
            mitreList.append("T1072 (Lateral Movement) Software Deployment Tools")
            T1072 = T1072 + 1
        if("crontab" in resultPerLine["command"]):
            mitreList.append("T1053 (Execution) Scheduled Task/Job")
            mitreList.append("T1053 (Persistence) Scheduled Task/Job")
            mitreList.append("T1053 (Privilege Escalation) Scheduled Task/Job")
            T1053 = T1053 + 1
        if("service" in resultPerLine["command"] and "start" in resultPerLine["command"] or "service" in resultPerLine["command"] and "stop" in resultPerLine["command"] or "systemctl" in resultPerLine["command"] and "start" in resultPerLine["command"] or "systemctl" in resultPerLine["command"] and "stop" in resultPerLine["command"]):
            mitreList.append("T1569 (Execution) System Service")
            T1569 = T1569 + 1


        if("passwd" in resultPerLine["command"] or "usermod" in resultPerLine["command"]):
            mitreList.append("T1098 (Persistence) Account Manipulation")
            T1098 = T1098 + 1
        if("crontab" in resultPerLine["command"]):
            mitreList.append("T1547 (Persistence) Boot or Logon Autostart Execution")
            mitreList.append("T1547 (Privilege Escalation) Boot or Logon Autostart Execution")
            T1547 = T1547 + 1
        if("crontab" in resultPerLine["command"]):
            mitreList.append("T1037 (Persistence) Boot or Logon Initialization Scripts")
            mitreList.append("T1037 (Privilege Escalation) Boot or Logon Initialization Scripts")
            T1037 = T1037 + 1
        #if("curl" in resultPerLine["command"]):
        #    mitreList.append("T1554 (Persistence) Compromise Client Software Binary")
        #    T1098 = T1098 + 1
        if("useradd" in resultPerLine["command"]):
            mitreList.append("T1136 (Persistence) Create Account")
            T1136 = T1136 + 1
        if("nano" in resultPerLine["command"] and ".service" in resultPerLine["command"]):
            mitreList.append("T1543 (Persistence) Create or Modify System Process")
            mitreList.append("T1543 (Privilege Escalation) Create or Modify System Process")
            T1543 = T1543 + 1
        if("cat" in resultPerLine["command"] and ".service" in resultPerLine["command"]):
            if "T1543 (Persistence) Create or Modify System Process" not in mitreList:
                mitreList.append("T1543 (Persistence) Create or Modify System Process")
                mitreList.append("T1543 (Privilege Escalation) Create or Modify System Process")
                T1543 = T1543 + 1
        if("less" in resultPerLine["command"] and ".service" in resultPerLine["command"]):
            if "T1543 (Persistence) Create or Modify System Process" not in mitreList:
                mitreList.append("T1543 (Persistence) Create or Modify System Process")
                mitreList.append("T1543 (Privilege Escalation) Create or Modify System Process")
                T1543 = T1543 + 1
        if("vim" in resultPerLine["command"] and ".service" in resultPerLine["command"]):
            if "T1543 (Persistence) Create or Modify System Process" not in mitreList:
                mitreList.append("T1543 (Persistence) Create or Modify System Process")
                mitreList.append("T1543 (Privilege Escalation) Create or Modify System Process")
                T1543 = T1543 + 1
        if("vi" in resultPerLine["command"] and ".service" in resultPerLine["command"]):
            if "T1543 (Persistence) Create or Modify System Process" not in mitreList:
                mitreList.append("T1543 (Persistence) Create or Modify System Process")
                mitreList.append("T1543 (Privilege Escalation) Create or Modify System Process")
                T1543 = T1543 + 1
#        if("system" in resultPerLine["command"]):
#            mitreList.append("T1053 (Persistence) Scheduled Task/Job")
        if("who" in resultPerLine["command"] or "passwd" in resultPerLine["command"]):
            mitreList.append("T1078 (Persistence) Valid Accounts")
            mitreList.append("T1078 (Privilege Escalation) Valid Accounts")
            mitreList.append("T1078 (Defense Evasion) Valid Accounts")
            T1078 = T1078 + 1
        if("/etc/passwd" in resultPerLine["command"] or "nano /etc/passwd" in resultPerLine["command"] or "cat /etc/passwd" in resultPerLine["command"] or "vi /etc/passwd" in resultPerLine["command"] or "vim /etc/passwd" in resultPerLine["command"] or "less /etc/passwd" in resultPerLine["command"]):
            mitreList.append("T1078 (Persistence) Valid Accounts")
            mitreList.append("T1078 (Privilege Escalation) Valid Accounts")
            mitreList.append("T1078 (Defense Evasion) Valid Accounts")
            T1078 = T1078 + 1
    

        if("HISTFILE" in resultPerLine["command"]):
            mitreList.append("T1564 (Defense Evasion) Hide Artifacts")
            T1564 = T1564 + 1
        if("rm /var/log" in resultPerLine["command"]):
            mitreList.append("T1070 (Defense Evasion) Indicator Removal on Host")
            T1070 = T1070 + 1
        if("chmod" in resultPerLine["command"]):
            mitreList.append("T1222 (Defense Evasion) File and Directory Permissions Modification")
            T1222 = T1222 + 1
        

        #if("system" in resultPerLine["command"]):
        #    mitreList.append("T1110 (Credential Access) Brute Force")
        #    T1098 = T1098 + 1
        if("pass" in resultPerLine["command"]):
            mitreList.append("T1555 (Credential Access) Credentials from Password Stores")
            T1555 = T1555 + 1
        if("/etc/passwd" in resultPerLine["command"] or "nano /etc/passwd" in resultPerLine["command"] or "cat /etc/passwd" in resultPerLine["command"] or "vi /etc/passwd" in resultPerLine["command"] or "vim /etc/passwd" in resultPerLine["command"] or "less /etc/passwd" in resultPerLine["command"]):
            if "T1555 (Credential Access) Credentials from Password Stores" not in mitreList:
                mitreList.append("T1555 (Credential Access) Credentials from Password Stores")
                T1555 = T1555 + 1
        if("ping" in resultPerLine["command"] or "telnet" in resultPerLine["command"]):
            mitreList.append("T1040 (Credential Access) Network Sniffing")
            mitreList.append("T1040 (Discovery) Network Sniffing")
            T1040 = T1040 + 1
        

        if(resultPerLine["command"] == "w" or "id" in resultPerLine["command"] or "who" in resultPerLine["command"] or "groups" in resultPerLine["command"] or "lastlog" in resultPerLine["command"] or "last" in resultPerLine["command"]):
            mitreList.append("T1087 (Discovery) Account Discovery")
            T1087 = T1087 + 1
        if("which " in resultPerLine["command"] or "ls" in resultPerLine["command"] or "cd " in resultPerLine["command"] or "dir" in resultPerLine["command"] or "tree" in resultPerLine["command"] or "find " in resultPerLine["command"] or "locate " in resultPerLine["command"] or "grep " in resultPerLine["command"] or resultPerLine["command"]=="pwd"):
            mitreList.append("T1083 (Discovery) File and Directory Discovery")
            T1083 = T1083 + 1
        if("nmblookup" in resultPerLine["command"]):
            mitreList.append("T1135 (Discovery) Network Share Discovery")
            T1135 = T1135 + 1
        #if("system" in resultPerLine["command"]):
        #    mitreList.append("T1040 (Discovery) Network Sniffing")
        #    T1040 = T1040 + 1
        if("/etc/pam.d/common-password" in resultPerLine["command"] or "less /etc/pam.d/common-password" in resultPerLine["command"] or "nano /etc/pam.d/common-password" in resultPerLine["command"] or "cat /etc/pam.d/common-password" in resultPerLine["command"] or "vi /etc/pam.d/common-password" in resultPerLine["command"] or "vim /etc/pam.d/common-password" in resultPerLine["command"]):
            mitreList.append("T1201 (Discovery) Password Policy Discovery")
            T1201 = T1201 + 1
        if("groups" in resultPerLine["command"]):
            mitreList.append("T1069 (Discovery) Permission Groups Discovery")
            T1069 = T1069 + 1
        if("top" in resultPerLine["command"] or "ps" in resultPerLine["command"] or "jobs" in resultPerLine["command"]):
            mitreList.append("T1057 (Discovery) Process Discovery")
            T1057 = T1057 + 1
        if("ping" in resultPerLine["command"]):
            mitreList.append("T1018 (Discovery) Remote System Discovery")
            T1018 = T1018 + 1
        if("apt list" in resultPerLine["command"] or "dpkg-query -l" in resultPerLine["command"]):
            mitreList.append("T1518 (Discovery) Software Discovery")
            T1518 = T1518 + 1
        if("/var/log/apt/history.log" in resultPerLine["command"] or "less /var/log/apt/history.log" in resultPerLine["command"] or "vim /var/log/apt/history.log" in resultPerLine["command"] or "cat /var/log/apt/history.log" in resultPerLine["command"] or "nano /var/log/apt/history.log" in resultPerLine["command"] or "vi /var/log/apt/history.log" in resultPerLine["command"]):
            if "T1518 (Discovery) Software Discovery" not in mitreList:
                mitreList.append("T1518 (Discovery) Software Discovery")
                T1518 = T1518 + 1
        if("free" in resultPerLine["command"] or "nproc" in resultPerLine["command"] or "lshw" in resultPerLine["command"] or "lscpu" in resultPerLine["command"] or "hostname" in resultPerLine["command"] or "uname" in resultPerLine["command"]):
            mitreList.append("T1082 (Discovery) System Information Discovery")
            T1082 = T1082 + 1
        if("/proc/version" in resultPerLine["command"] or "/proc/mounts" in resultPerLine["command"] or "proc/uptime" in resultPerLine["command"] or "/proc/cpuinfo" in resultPerLine["command"] or "less /proc/cpuinfo" in resultPerLine["command"] or "vim /proc/cpuinfo" in resultPerLine["command"] or "cat /proc/cpuinfo" in resultPerLine["command"] or "nano /proc/cpuinfo" in resultPerLine["command"] or "vi /proc/cpuinfo" in resultPerLine["command"]):
            if "T1082 (Discovery) System Information Discovery" not in mitreList:
                mitreList.append("T1082 (Discovery) System Information Discovery")
                T1082 = T1082 + 1
        if("ifconfig" in resultPerLine["command"] or "ipconfig" in resultPerLine["command"]):
            mitreList.append("T1016 (Discovery) System Network Configuration Discovery")
            T1016 = T1016 + 1
        if("netstat" in resultPerLine["command"]):
            mitreList.append("T1049 (Discovery) System Network Connections Discovery")
            T1049 = T1049 + 1
        if("who" in resultPerLine["command"] or "whoami" in resultPerLine["command"]):
            mitreList.append("T1033 (Discovery) System Owner/User Discovery")
            T1033 = T1033 + 1
        if("service" in resultPerLine["command"] and "status" in resultPerLine["command"] or "systemctl" in resultPerLine["command"] and "status" in resultPerLine["command"]):
            mitreList.append("T1007 (Discovery) System Service Discovery")
            T1007 = T1007 + 1


        if("scp " in resultPerLine["command"]):
            mitreList.append("T1570 (Lateral Movement) Lateral Tool Transfer")
            T1570 = T1570 + 1
        #if("system" in resultPerLine["command"]):
        #    mitreList.append("T1021 (Lateral Movement) Remote Services")
        #    T1021 = T1021 + 1
        #if("curl" in resultPerLine["command"]):
        #    mitreList.append("T1072 (Lateral Movement) Software Deployment Tools")
        #    T1072 = T1072 + 1


        if("zip" in resultPerLine["command"] or "tar" in resultPerLine["command"] or "gzip" in resultPerLine["command"]):
            mitreList.append("T1560 (Collection) Archive Collected Data")
            T1560 = T1560 + 1
        if("pbpaste" in resultPerLine["command"]):
            mitreList.append("T1115 (Collection) Clipboard Data")
            T1115 = T1115 + 1
        if("cp " in resultPerLine["command"] or "cat " in resultPerLine["command"] or "less " in resultPerLine["command"] or "vim " in resultPerLine["command"] or "vi " in resultPerLine["command"] or "nano " in resultPerLine["command"]):
            mitreList.append("T1005 (Collection) Data from Local System")
            T1005 = T1005 + 1


        if("scp " in resultPerLine["command"] or "git" in resultPerLine["command"] or "wget" in resultPerLine["command"]):
            mitreList.append("T1105 (Command and Control) Ingress Tool Transfer")
            T1105 = T1105 + 1


        if("wget http" in resultPerLine["command"]):
            mitreList.append("T1567 (Exfiltration) Exfiltration Over Web Service")
            T1567 = T1567 + 1


        if("userdel" in resultPerLine["command"]):
            mitreList.append("T1531 (Impact) Account Access Removal")
            T1531 = T1531 + 1
        if("rm " in resultPerLine["command"]):
            mitreList.append("T1485 (Impact) Data Destruction")
            T1485 = T1485 + 1
        if("gpg" in resultPerLine["command"]):
            mitreList.append("T1486 (Impact) Data Encrypted for Impact")
            T1486 = T1486 + 1
        if("cat " in resultPerLine["command"] or "less " in resultPerLine["command"] or "vim " in resultPerLine["command"] or "vi " in resultPerLine["command"] or "nano " in resultPerLine["command"]):
            mitreList.append("T1565 (Impact) Data Manipulation")
            T1565 = T1565 + 1
        if("wipe" in resultPerLine["command"] or "dd " in resultPerLine["command"]):
            mitreList.append("T1561 (Impact) Disk Wipe")
            T1561 = T1561 + 1
        if("service" in resultPerLine["command"] and "stop" in resultPerLine["command"] or "systemctl" in resultPerLine["command"] and "stop" in resultPerLine["command"]):
            mitreList.append("T1489 (Impact) Service Stop")
            T1489 = T1489 + 1
        if("reboot" in resultPerLine["command"] or "shutdown" in resultPerLine["command"]):
            mitreList.append("T1529 (Impact) System Shutdown/Reboot")
            T1529 = T1529 + 1


    for j in range(len(mitreList)):
        mitre = mitreList[j] + " | " + mitre

    with open(resultName, 'ab') as csvfile:
        writer = csv.writer(csvfile)
        if(i == 0):
            writer.writerow(["Log File Name:", fileLog])
            writer.writerow(["Time Stamp", "Action Type", "Session", "IP", "Command List", "List Mitre Attack"])
            writer.writerow([resultPerLine["timestamp"], resultPerLine["actionType"], resultPerLine["session"], resultPerLine["source_ip"], str(resultPerLine["command"]), mitre])
        elif (i == len(data) - 1):
            writer.writerow([resultPerLine["timestamp"], resultPerLine["actionType"], resultPerLine["session"], resultPerLine["source_ip"], str(resultPerLine["command"]), mitre])
            writer.writerow([" "])
            writer.writerow(["Total per list Mitre ATT&CK"])
            writer.writerow(["T1595 Active Scanning", T1595])
            writer.writerow(["T1059 Command and Scripting Interpreter", T1059])
            writer.writerow(["T1559 Inter-Process Communication", T1559])
            writer.writerow(["T1569 System Services", T1569])
            writer.writerow(["T1098 Account Manipulation", T1098])
            writer.writerow(["T1547 Boot or Logon Autostart Execution", T1547])
            writer.writerow(["T1078 Valid Accounts", T1078])
            writer.writerow(["T1554 Compromise Client Software Binary", T1554])
            writer.writerow(["T1136 Create Account", T1136])
            writer.writerow(["T1543 Create or Modify System Process", T1543])
            writer.writerow(["T1037 Boot or Logon Initialization Scripts", T1037])
            writer.writerow(["T1053 Scheduled Task/Job", T1053])
            writer.writerow(["T1564 Hide Artifacts", T1564])
            writer.writerow(["T1222 File and Directory Permissions Modification", T1222])
            writer.writerow(["T1070 Indicator Removal on Host", T1070])
            writer.writerow(["T1110 Brute Force", T1110])
            writer.writerow(["T1555 Credentials from Password Stores", T1555])
            writer.writerow(["T1087 Account Discovery", T1087])
            writer.writerow(["T1083 File and Directory Discovery", T1083])
            writer.writerow(["T1135 Network Share Discovery", T1135])
            writer.writerow(["T1040 Network Sniffing", T1040])
            writer.writerow(["T1201 Password Policy Discovery", T1201])
            writer.writerow(["T1069 Permission Groups Discovery", T1069])
            writer.writerow(["T1057 Process Discovery", T1057])
            writer.writerow(["T1018 Remote System Discovery", T1018])
            writer.writerow(["T1518 Software Discovery", T1518])
            writer.writerow(["T1082 System Information Discovery", T1082])
            writer.writerow(["T1016 System Network Configuration Discovery", T1016])
            writer.writerow(["T1049 System Network Connections Discovery", T1049])
            writer.writerow(["T1033 System Owner/User Discovery", T1033])
            writer.writerow(["T1007 System Service Discovery", T1007])
            writer.writerow(["T1570 Lateral Tool Transfer", T1570])
            writer.writerow(["T1021 Remote Services", T1021])
            writer.writerow(["T1072 Software Deployment Tools", T1072])
            writer.writerow(["T1560 Archive Collected Data", T1560])
            writer.writerow(["T1115 Clipboard Data", T1115])
            writer.writerow(["T1005 Data from Local System", T1005])
            writer.writerow(["T1105 Ingress Tool Transfer", T1105])
            writer.writerow(["T1567 Exfiltration Over Web Service", T1567])
            writer.writerow(["T1531 Account Access Removal", T1531])
            writer.writerow(["T1485 Data Destruction", T1485])
            writer.writerow(["T1486 Data Encrypted for Impact", T1486])
            writer.writerow(["T1565 Data Manipulation", T1565])
            writer.writerow(["T1561 Disk Wipe", T1561])
            writer.writerow(["T1489 Service Stop", T1489])
            writer.writerow(["T1529 System Shutdown/Reboot", T1529])
            
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
redirectURL2 = "http://localhost:8080/downloadResult.php?log=" + fileLog + "&result=" + resultName
print('<html>')
print('  <head>')
print('    <meta http-equiv="refresh" content="0;url='+str(redirectURL2)+'" />')
print('  </head>')
print('</html>')    