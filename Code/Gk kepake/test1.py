with open("CowrieLogAnalyzeResult " + str(date.today()) + ".csv", 'ab') as csvfile:
                writer = csv.writer(csvfile)
                if(i == 0):
                    writer.writerow(["Time Stamp", "Action Type", "Session", "IP", "Command List", "List Mitre Attack"])
                    writer.writerow([resultPerLine["timestamp"], resultPerLine["actionType"], resultPerLine["session"], resultPerLine["source_ip"], resultPerLine["command"], mitre])
                else:
                    writer.writerow([resultPerLine["timestamp"], resultPerLine["actionType"], resultPerLine["session"], resultPerLine["source_ip"], resultPerLine["command"], mitre])