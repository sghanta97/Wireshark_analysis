# Wireshark_analysis
To be able to analyze packet capture more easily using python scripts


## Packet_filter.py 
This script can be used to generate a readable csv format of only required feilds in a packet capture.  

To use: python3 Packet_filter.py <file.pcap>.   
Output: output.csv


## Packet_diff.py 
This script can be used to compare two packet captures taken on opposite ends of a transport link and be used to identify if there is any packet loss.
If there is any packet loss. The script identifies them and stores those packets in output. 

To use: python3 Packet_diff.py <file.pcap>  
Output: output.csv
# ignore first and last copule of packets (might not be captured on both ends)



### Note:
* The script will erase prevois output.csv when run again. So save outputs before running the script multiple times.  
* And also add the required feilds in the feilds array: default values are Src Ip, Dst Ip, Src prt, Dst prt and  Protocol 
