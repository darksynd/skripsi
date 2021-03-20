import sys
import json
import csv

FileName = "cowrie.json.2021-01-03"
FilePath = "../Pengujian/logs/" + FileName

PathParsed = "../Pengujian/parsed/"
parsed = PathParsed + "Parsed" + FileName + ".txt"
data = []

resultPerLine = {
    "cetak": "",
}

f = open(FilePath, "r")
outF = open(parsed, "w")
for line in f:
    if("cowrie.command.input" in line):
        outF.write(line)
outF.close()