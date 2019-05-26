import os
import re

filePath = "./ssh.log.txt"
fd = open(filePath, 'r')

total_scan_attempts = 0
nmap_scan_attempts = 0
host_ips = []
destination_ips = []
#scanner to count total attempts and threat attempts
with fd as reader :
    for line in reader :
        total_scan_attempts += 1
        if "Nmap" in line:
            nmap_scan_attempts += 1
            host_ips.append(line.split("\t")[2])
            destination_ips.append(line.split("\t")[4])
#write results to scanners_found.txt
f = open("scanners_found.txt", "w")
f.write("Total Scan Attempts " + str(total_scan_attempts) + "\n")
f.write("Malicious Scan Attempts " + str(nmap_scan_attempts) + "\n\n")
#write new line for origin hosts
f.write("Scan origin hosts" + "\n")
for ip in host_ips:
    f.write("\t" + str(ip) + "\n")
#write new line for destination hosts
f.write("\nScan destination hosts" + "\n")
for ip in host_ips:
    f.write("\t" + str(ip) + "\n")

f.close()