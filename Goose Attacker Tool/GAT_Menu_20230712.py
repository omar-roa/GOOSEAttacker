import os
import GAT_Main_20230712 as Main

def Menu():#Starting Menu
    option = True
    while option:
        print(f'Welcome to GOOSE Attacker Tool \nWhen it is required to write the number of the specific option\n')
        attack_choose = input(
            'Select the attack:\n 1) DoS\n 2) Spoofing\n 3) Replay\n 4) FDI\n 0) Exit\n')
        try:
            if (attack_choose == ''):
                os.system('clear')
                print(f'Please enter a option')
            elif (int(attack_choose) == 0):
                print(f'Goodbye')
                break
            else:
                option = Main.Options(int(attack_choose))
        except ValueError:
            # os.system('clear')
            print(f'{attack_choose} is not a valid option\nPlease enter a valid option')

    print(f'The attack has finished\nGoodbye')
    
Menu()