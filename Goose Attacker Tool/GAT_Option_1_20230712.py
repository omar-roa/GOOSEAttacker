import scapy.all as scapy
import logging
import time
import GAT_Main_20230712 as Main

def sniffed(packet):
    global dst_aux
    global src_aux
    global flag
    global save_packet
    global current_time
    global execution_time
    global start_time

    dict_tags = {}

    try:
        if (Main.filter_GOOSE(packet) == True):#Filter by GOOSE protocol
            packet.dst = dst_aux
            packet.src = src_aux
            new_load = None
            previous_load, working_load = Main.separation_load(packet) #Separate packet load

            if (flag == 1):
                    previous_reserved = Main.flags_reserved(previous_load,option_selected) #Set reserved field
                    new_load = previous_reserved
            elif (flag == 0):
                    new_load = previous_load

            dict_tags = Main.dict_separation(working_load) #Classificate tags of packet
            if (start_time == 0):
                start_time = time.time()
            current_time = time.time()

            if (save_packet == 1):
                Main.packet_capture(packet,option_selected,flag) #Save packet in pcap file

            for j in dict_tags: #Encapsulate of the package
                new_load += 25*(j[1]+dict_tags.get(j)) # creation of the new load of the message
            packet.load = new_load

            if (current_time == 0 or (current_time-start_time) < execution_time):
                while((current_time-start_time)<=execution_time):
                    scapy.sendp(packet, iface='eno1', inter=0, count=10000, verbose=False) # send the modify packet to the network
                    current_time = time.time()
                    print(f'Elapsed time = {current_time-start_time}')
                raise KeyboardInterrupt
        if ((current_time-start_time) >= execution_time):
            raise KeyboardInterrupt

    except Exception as e:
        # print(repr(e))
        if (str(e) == "int too big to convert"):
            logging.exception('Exception')
            print(
                f'Source = {packet.src} Destination = {packet.dst} \n {packet.show}')
            time.sleep(5)
            raise
        elif (str(e) != 'type'):
            logging.exception('Exception')
            print(repr(e))
            raise
        else:
            pass


def start(values,option): #Set initial values
    global dst_aux
    dst_aux = values[0]
    global src_aux
    src_aux = values[1]
    global flag
    flag = values[2]
    global save_packet
    save_packet = values[3]
    global execution_time
    execution_time = values[4]
    global data_values
    data_values = values
    global burst
    burst = []
    global option_selected
    option_selected = option

    global current_time
    global start_time

    start_time = 0
    current_time = 0

    a = scapy.sniff(offline='Ex_GOOSE.pcap', iface='eno1', prn=sniffed)