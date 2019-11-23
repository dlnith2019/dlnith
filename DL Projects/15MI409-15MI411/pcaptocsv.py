import pyshark #for interfacing with tshark
import csv #for reading and writing to csv files
import time #for time related operations
import datetime
from timeit import default_timer as timer #for timing tasks and functions in programme

IP_whitelist = ['192.168.1.1', '192.168.1.2', '192.168.1.3', '192.168.1.4'] #List of IP's that you are sure won't be DDOSing your system.
def ipa_type(packet): #Differentiate between IPv4 and IPv6
    for layer in packet.layers:
        if layer._layer_name == 'ip':
            return 4
        elif layer._layer_name == 'ipv6':
            return 6

def pcaptocsv(cap): # For each packet in capture, extracts features
    start_time = time.time() #for flow rate calculation
    with open('Data1.csv', 'w', newline='') as csvfile: #open statically named Data.csv with write privs, will overwrite previous one
        fwriter = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL) # csv.writer writes a csv file using specified delimiters quote characters
        fwriter.writerow( #writes a row, here first one with headings of features to extract and evaluate on
            ['Highest Layer', 'Transport Layer', 'Source IP', 'Dest IP', 'Source Port', 'Dest Port',
             'Packet Length', 'Packets/Time', 'target'])

        i = 0
        start = timer() #timing each packet feature extraction
        for packet in cap:
            end = timer()
            try:
                        if packet.highest_layer != 'ARP': # checks if it is a packet or a frame, if true then packet else frame
                            ip = None #define basic variable for storing ip
                            ipa = ipa_type(packet) #call a function which returns ip addressing type (v4 or v6)
                            if ipa == 4:
                                ip = packet.ip #extract v4 ip from packet
                                ipv = 0  #flag depicting only v4 ip address type
                                if packet.transport_layer == None: #checks if the packet has a layer 4 protocol specified
                                    transport_layer = 'None' #if not set as none
                                else:
                                    transport_layer = packet.transport_layer #else set as the value
                            elif ipa == 6:
                                ip = packet.ipv6#extract v6 ip from packet
                                ipv = 1  #flag depicting only v6 ip address type

                            try:
                                if ip.src not in IP_whitelist: #check for source ip in whitelist
                                    ipcat = 1
                                    target = 1 #if not then this flag tells NN model to consider this packet for ddos detection
                                else:
                                    ipcat = 0
                                    target = 0 #else don't
                                fwriter.writerow([packet.highest_layer, transport_layer, ip.src, ip.dst,
                                                     packet[packet.transport_layer].srcport,
                                                     packet[packet.transport_layer].dstport,
                                                     packet.length, i / (time.time() - start_time), target]) #write all this info to csv
                                i += 1
                            except AttributeError:
                                if ip.src not in IP_whitelist: #checking whitelist for ip even if error occurs
                                    ipcat = 1
                                    target = 1
                                else:
                                    ipcat = 0
                                    target = 0
                                fwriter.writerow(
                                    [packet.highest_layer, transport_layer, ipcat, ip.dst, 0, 0,
                                     packet.length, i / (time.time() - start_time), target]) #write to csv even if no transport layer ports were found
                                print("Time: ", time.time() - start_time)
                                print("Packets Collected:", i)
                                i += 1 #Increment packet collected counter for next run

                        else:
                            if packet.arp.src_proto_ipv4 not in IP_whitelist: #whitelist check for ipv4 source ip packets
                                ipcat = 1
                                target = 1
                            else:
                                ipcat = 0
                                target = 0
                            arp = packet.arp #protoocol save
                            fwriter.writerow(
                                [packet.highest_layer, transport_layer, ipcat, arp.dst_proto_ipv4, 0, 0,
                                 packet.length, i / (time.time() - start_time), target]) # write to csv
                            print("Time: ", time.time() - start_time)
                            print("Packets Collected:", i)
                            i += 1 #increment collected packets counter
            except (UnboundLocalError, AttributeError) as e:
                pass
def main():
	capture_name = input("Enter filename for capture file(.pcap)\n") #get name of pcap file
	cap = pyshark.FileCapture(capture_name) #open pcap file as a tshark object using pyshark
	pcaptocsv(cap) #call pcaptocsv passing on the tshark object to it.
main()
