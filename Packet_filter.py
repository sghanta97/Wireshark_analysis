import pyshark
import csv
import os
import sys

FIELDS = (
    "srcaddr",
    "dstaddr",
    "srcport",
    "dstport",
    "protocol",
    "octets",
    "permanent_octets"
)


def parse_cflow_packet(packet_cflow):
    flows = []
    for field_idx, field in enumerate(FIELDS):
        field_exists = hasattr(packet_cflow, field)
        if not field_exists:
            continue

        if field_idx == 0:
            for flow_number, value in enumerate(
                getattr(packet_cflow, field).all_fields
            ):
                flows.append({field: value.showname_value})
            continue

        for flow_number, value in enumerate(getattr(packet_cflow, field).all_fields):
            #print(value.showname_value)
            flows[flow_number][field] = value.showname_value 
    return flows

capture = pyshark.FileCapture(sys.argv[1])
 
all_flows = []

pkt_count=0
for packet in capture:
    pkt_count+=1	     
    packet_flows = parse_cflow_packet(packet.cflow)
    all_flows.extend(packet_flows)
print("packet count: "+str(pkt_count))

if os.path.exists("output.csv"):
  os.remove("output.csv")

octets=0
permanent_octets=0

with open("output.csv", 'w') as csvfile:    
    csvwriter = csv.writer(csvfile)    
    csvwriter.writerow(FIELDS)   
    for mapping in all_flows:
        octets+=int(mapping["octets"])   
        permanent_octets+=int(mapping["permanent_octets"])
        row=[mapping["srcaddr"],mapping["dstaddr"],mapping["srcport"],mapping["dstport"],mapping["protocol"],mapping["octets"],mapping["permanent_octets"]]
        csvwriter.writerow(row)
print("octets: "+ str(octets))
print("permanent_octets: "+ str(permanent_octets))
