import GAT_Option_2_20230712 as Option_2
import GAT_Option_3_20230712 as Option_3
import GAT_Option_1_20230712 as Option_1
import GAT_Option_4_20230712 as Option_4
import GAT_Text_20230712 as Text
import os
import scapy.all as scapy
from multiprocessing import Pipe
import datetime


def Options(option): #Menu and initializing variables
    match int(option):
        case (1):
            values = Text.Options_selected(option)
            Option_1.start(values,option)
        case (2):
            values = Text.Options_selected(option)
            Option_2.start(values,option)
        case (3):
            values = Text.Options_selected(option)
            Option_3.start(values,option)
        case (4):
            values = Text.Options_selected(option)
            Option_4.start(values,option)
        case _:
            os.system('clear')
            print(f'{option} is a invalid option please enter ')
            return option
    return False


def filter_GOOSE(packet):#Filter by GOOSE protocol
    try:
        if (packet.type == 35000):
            return True
        else:
            return False
    except:
        pass


def filter_MAC(packet_dst, packet_src, dst, src):#Filter by MAC desired
    if (packet_dst == dst and packet_src == src):
        return True
    else:
        return False


def separation_load(packet):#Separation of package load by date tag b'\x84'
    tag_date = packet.load.index(b'\x84')
    previous = packet.load[:tag_date]
    working = packet.load[tag_date:]
    date_catched = False
    while (date_catched == False):
        if (packet.load[tag_date+1] == 8):
            if (packet.load[tag_date+10] == 133):
                date_catched = True
        else:
            tag_date += 1
            previous = packet.load[:tag_date]
            working = packet.load[tag_date:]
            tag_date = working.index(b'\x84')+tag_date

    return previous, working


def dict_separation(working_load):#Classification of tags on goosepdu starting in date tag b'\x84'
    dict_tags = {}
    len_packet = 0
    load_position = 0
    for i in working_load:
        values = 0
        if (len_packet == 0):
            i = working_load[0]
            dic_key = int.to_bytes(i, 1, 'big')
            values = working_load[1]
            dict_tags.setdefault((load_position, dic_key),
                                 working_load[1:values+2])
            len_packet = values+1
            new_working_load = working_load
        elif (len_packet < len(new_working_load)):
            new_working_load = new_working_load[len_packet+1:]
            if (new_working_load == b''):
                break
            i = new_working_load[0]
            dic_key = int.to_bytes(i, 1, 'big')
            values = new_working_load[1]
            dict_tags.setdefault((load_position, dic_key),
                                 new_working_load[1:values+2])
            len_packet = values+1
        else:
            break
        load_position += 1
    return dict_tags


def dict_separation_2(working_load):#Simpler version of classification of tags on goosepdu starting in date tag b'\x84'
    dict_tags = {}
    len_packet = 0
    for i in working_load:
        values = 0
        if (len_packet == 0):
            i = working_load[0]
            dic_key = int.to_bytes(i, 1, 'big')
            values = working_load[1]
            dict_tags.setdefault(dic_key,
                                 working_load[1:values+2])
            len_packet = values+1
            new_working_load = working_load
        elif (len_packet < len(new_working_load)):
            new_working_load = new_working_load[len_packet+1:]
            if (new_working_load == b''):
                break
            i = new_working_load[0]
            dic_key = int.to_bytes(i, 1, 'big')
            values = new_working_load[1]
            dict_tags.setdefault(dic_key,
                                 new_working_load[1:values+2])
            len_packet = values+1
        else:
            break
    return dict_tags

def watcher_burst(values,side_B):#Multiprocessing method to start watch if burst raised
    global data_values
    global connection
    data_values = values
    connection = side_B
    StNum = scapy.sniff(iface='eno1', lfilter=filter_GOOSE, store=0,
                prn=checker_burst, timeout = data_values[-2])

def watcher_status(values,side_B):#Multiprocessing method to start watch status number
    global data_values
    global connection
    connection = side_B
    data_values = values
    StNum = scapy.sniff(iface='eno1', lfilter=filter_GOOSE, store=0,
                prn=checker_status, timeout = data_values[-1])

def checker_status(packet):#Multiprocessing method only to catch status number
    global connection
    if (filter_MAC(packet.dst, packet.src, data_values[0], data_values[1])):
        previous_load, working_load = separation_load(packet)
        reserved_tag = check_reserved(previous_load)
        if (reserved_tag == False):
            dict_tags = dict_separation_2(working_load)
            StNum = [(int.from_bytes(dict_tags.get(
                b'\x85')[1:], byteorder="big")), dict_tags.get(b'\x84')[1:]]
            connection.send(StNum)

def checker_burst(packet):#Multiprocessing method to catch burst
    global connection
    StNum = check(packet, data_values)
    connection.send(StNum)

def check_StNum(values, dict_tags):#Multiprocessing method to catch changes in status number
    actual_status = (int.from_bytes(dict_tags.get(
        b'\x85')[1:], byteorder="big"))
    if (actual_status > values):
        return True
    else:
        return False


def check(packet, values):#Multiprocessing method to proccess packet
    if (filter_MAC(packet.dst, packet.src, values[0], values[1])):
        previous_load, working_load = separation_load(packet)
        reserved_tag = check_reserved(previous_load)
        if (reserved_tag == False):
            dict_tags = dict_separation_2(working_load)
            StNum = check_StNum(values[-1], dict_tags)
            return [StNum, dict_tags.get(b'\x85')[1:], dict_tags.get(b'\x84')[1:]]
    else:
        return [False, 0, 0]

def check_reserved(previous_load):#Filter if reserved tag is modified
    aux = previous_load.index(b'\x61')
    ax = previous_load[aux-3]
    if (int(ax)!=0):
        return True
    else:
        return False

def packet_capture(packet,option,flag):#Save the packet in pcap file
    if (datetime.datetime.now().month <= 9):
        month = '0'+str(datetime.datetime.now().month)
    else:
        month = datetime.datetime.now().month

    if (datetime.datetime.now().day <= 9):
        day = '0'+str(datetime.datetime.now().day)
    else:
        day = datetime.datetime.now().day

    if (flag == 0):
        name_pcap = str(datetime.datetime.now().year)+str(month) + \
            str(day)+"-lab-Option-0"+str(option)+"-Ntag.pcap"
    elif (flag == 1):
        name_pcap = str(datetime.datetime.now().year)+str(month) + \
            str(day)+"-lab-Option-0"+str(option)+"-Ytag.pcap"
        
    try:
        file_pcap = f'PCAP_FILES/{name_pcap}'
        scapy.wrpcap(file_pcap, packet, append=True)
    except:
        os.mkdir('PCAP_FILES', mode=0o777)
        file_pcap = f'PCAP_FILES/{name_pcap}'
        scapy.wrpcap(file_pcap, packet, append=True)

def flags_reserved(previous_load, option):#Change reserved field
    aux = previous_load.index(b'\x61')
    option_insert = int(option)
    new_option = option_insert.to_bytes(1, byteorder='big')
    previous_reserved = previous_load[:aux-3]+new_option+previous_load[aux-2:]
    return previous_reserved

def interval_time(dict_tags, packet,dict_time, attack_time):#Calculate interval time between 2 packets
    aux = tuple([i for i in dict_tags if i[1] == b'\x84'])
    aux = aux[0]
    time_now = datetime.datetime.now()
    if (dict_time.get(packet.dst)):
        dict_time.get(packet.dst).append([aux, time_now])
    else:
        dict_time.setdefault(packet.dst, [[dict_tags.get(aux)[1:], time_now],])
    if (len(dict_time.get(packet.dst)) == 2):
        ax = (((dict_time.get(packet.dst)[-1][1].minute*60)+(dict_time.get(packet.dst)[-1][1].second))-(
            (dict_time.get(packet.dst)[0][1].minute*60)+(dict_time.get(packet.dst)[0][1].second)))
        attack_time = int(ax)-0.1
    if (attack_time != None):
        return attack_time, dict_time
    else:
        return 0, dict_time
    
def interval_time_5(dict_tags, packet,dict_time, attack_time):#Calculate interval time between 5 packets
    aux = tuple([i for i in dict_tags if i[1]==b'\x84'])
    aux = aux[0]
    time_now = datetime.datetime.now()
    if(dict_time.get(packet.dst)):
        dict_time.get(packet.dst).append([aux,time_now])
    else:
        dict_time.setdefault(packet.dst,[[dict_tags.get(aux)[1:],time_now],])
    if(len(dict_time.get(packet.dst))==5):
        ax = (((dict_time.get(packet.dst)[4][1].minute*60)+(dict_time.get(packet.dst)[4][1].second))-((dict_time.get(packet.dst)[0][1].minute*60)+(dict_time.get(packet.dst)[0][1].second)))
        attack_time = int(ax)/5
    if (attack_time != None):
        return attack_time, dict_time
    else:
        return 0, dict_time