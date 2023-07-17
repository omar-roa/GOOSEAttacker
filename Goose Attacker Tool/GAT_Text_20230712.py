def Options_selected(option):
    Title_attack(option)
    dst_aux = input('Enter the destination MAC\n') or '01:0c:cd:01:00:05'
    src_aux = input('Enter the source MAC\n') or '00:21:c1:24:85:86'
    flag = int(input('Turn on the flag? \n 0) No \n 1) Yes\n') or 0)
    save_packet = int(
        input('Do You want to save the packets? \n 0) No \n 1) Yes\n') or 0)
    execution_time = int(
                input('Define the time in seconds to run the attack ') or 60)

    match int(option):
        case (1):
            if(dst_aux == '01:0c:cd:01:00:05'):
                dst_aux = '01:0c:cd:01:01:04'
            if(src_aux == '00:21:c1:24:85:86'):
                src_aux = '00:21:c1:24:90:a0'
            return (dst_aux, src_aux, flag, save_packet, execution_time)
        case (2):
            return (dst_aux, src_aux, flag, save_packet, execution_time)
        case (3):
            replay_time = int(
                input('Define the time in seconds to replay the packet ') or 10)
            return (dst_aux, src_aux, flag, save_packet, execution_time, replay_time)
        case (4):
            return (dst_aux, src_aux, flag, save_packet, execution_time)
        
    return (dst_aux, src_aux, flag, save_packet)

def Title_attack(option):
    match int(option):
        case (1):
            print('DoS')
        case (2):
            print(f'SPOOFING')
        case (3):
            print(f'REPLAY')
        case (4):
            print(f'FDI')
        