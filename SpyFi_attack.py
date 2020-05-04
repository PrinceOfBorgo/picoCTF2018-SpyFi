from pwn import *
from codecs import decode
from colorama import Fore, Style
import colorama
import string

colorama.init()

# Suppress connection output
context.log_level = 'error'

### PLAINTEXT FORMAT
# """Agent,
# Greetings. My situation report is as follows:
# {0}  <--- input
# My agent identifying code is: {1}. <--- flag
# Down with the Soviets,
# 006
# """
# message_len = 113 + input_len + flag_len
# 113 + input_len + flag_len > 160 <--> input_length > 47 - flag_len <--> input_length >= 48 - flag_len
# max_len_to_stay_in_block = 9 ---> flag_len = 48 - (9+1) = 38
#
# flag_start = 84 + input_len ---> if input_len = 12 ---> flag_start = 96 = 0x60 (start seventh block)
# flag_end = flag_start + 38 ---> if input_len = 6 ---> flag_end = 128 = 0x80 (start of eighth block) 
#
#
# input_start = 53 = 0x35 (fourth block)
# if input_len >= 12, then input_end >= 53 + 11 = 64 = 0x40 (start fifth block)
#

def send_recv(input):
    r = remote("2018shell.picoctf.com", port)
    r.sendlineafter(": ", input)
    return r.recvall()[:-1]

def get_bytes(hex):
    return decode(hex, "hex")

def compare(s1, s2):
    if len(s1) != len(s2):
        return
    res=""
    for i in range(len(s1)):
        if s1[i] != s2[i]:
            res += hex(i)[2:] + " "
        else:
            res += "_"
    return res

def get_block(bytes, i):
    start = i*0x10
    return bytes[start:start+16]

def send_recv_block(input, i):
    return get_block(get_bytes(send_recv(input)), i)

def are_equal(s1, s2):
    if len(s1) != len(s2):
        return False
    for i in range(len(s1)):
        if s1[i] != s2[i]:
            return False
    return True

### EXECUTE TO GET padding_len, message_len, flag_len
# l = len(send_recv(""))
#
# ans = "x"
# i = 0
# while True:
#   if len(send_recv(ans)) != l:
#       break
#   else:
#       i += 1
#       ans += "x"                              |----------------|-------000000000|
#                                               |-----xxxxxxxx---|---------------0|
# max_len_to_stay_in_block = i                  |-----xxxxxxxxx--|----------------|
# padding_len = i                               |-----xxxxxxxxxx-|----------------|-000000000000000|
# message_len = l//2 - padding_len              |-----xxxxxxxxxxx|x---------------|---0000000000000|
# flag_len = message_len - 113

### PRECALCULATED WITH PREVIOUS ROUTINE
# max_len_to_stay_in_block = 9
# padding_len = 9
# message_len = 151
# flag_len = 38
# print("message_len: %d\npadding_len: %d\nflag_len: %d" %(message_len, padding_len, flag_len))



### flag_start = 84 + input_len ---> if input_len = 12 ---> flag_start = 96 = 0x60 (start seventh block)
### input_len = 12 - i ---> first i bytes of flag at the end of block [0x50,0x5f]
###
### x...x = input, ?...? = flag, addresses in hex
###                        30↓  35↓         40↓              50↓              60↓              70↓
### input_len = 12  ---->   |-----xxxxxxxxxxx|x---------------|----------------|????????????????|...
###                        30↓  35↓         40↓              50↓            5f↓
### input_len = 11  ---->   |-----xxxxxxxxxxx|----------------|---------------?|????????????????|...
###
### block [0x50,0x5f] = |---------------?| where first 15 bytes are known   |fying code is: ?|
###                                                                         |---------------?|
### Replacing all possibile char in ? we can pass this string as input prepended by 11 bytes
###                                                30↓  35↓         40↓              50↓              
### input = 11 bytes + "fying code is: ?"  ---->    |-----xxxxxxxxxxx|fying code is: ?|----------------|...
### This way we can compare the currently encrypted [0x40,0x4f] block with the previously encrypted [0x50,0x5f] block.
### That's a simplification, see below to see how it should be realy done.
###
### We can assume that flag starts with "picoCTF{" and ends with "}" so we can avoid the research of the first 8 and last 1 bytes of the flag
### flag_len = 38 ---> we must find only 29 bytes (the ones between the curly brackets)
### 
###                        30↓  35↓         40↓              50↓              60↓              70↓
### input_len = 12  ---->   |-----xxxxxxxxxxx|x---------------|----------------|picoCTF{????????|...
###                             35↓         40↓              50↓            5f↓
### input_len = 11  ---->   |-----xxxxxxxxxxx|----------------|---------------p|icoCTF{?????????|...
###                             35↓         40↓              50↓            5f↓
### input_len = 3   ---->   |-----xxx--------|----------------|-------picoCTF{?|????????????????|...
###                             35↓         40↓              50↓            5f↓
### input_len = 0   ---->   |----------------|----------------|----picoCTF{????|????????????????|...
### Using an initial input of 11 bytes we can recover only 4 bytes after "picoCTF{" looking at block [0x50,0x5f]
###
###                        30↓  35↓         40↓              50↓              60↓              70↓
### input_len = 28  ---->   |-----xxxxxxxxxxx|xxxxxxxxxxxxxxxx|x---------------|----------------|picoCTF{????????|...
###                             35↓         40↓              50↓              60↓            6f↓
### input_len = 27  ---->   |-----xxxxxxxxxxx|xxxxxxxxxxxxxxxx|----------------|---------------p|icoCTF{?????????|...
###                             35↓         40↓              50↓              60↓            6f↓
### input_len = 19   ---->  |-----xxxxxxxxxxx|xxxxxxxx--------|----------------|-------picoCTF{?|????????????????|...
###                             35↓         40↓              50↓              60↓            6f↓
### input_len = 0   ---->   |----------------|----------------|----picoCTF{????|????????????????|?????????}------|...
### Even using an initial input of 27 bytes is not enough: we can recover only 20 bytes after "picoCTF{" looking at block [0x60,0x6f]
###
###                        30↓  35↓         40↓              50↓              60↓              70↓            7f↓
### input_len = 35  ---->   |-----xxxxxxxxxxx|xxxxxxxxxxxxxxxx|xxxxxxxx--------|----------------|-------picoCTF{?|????????????????|...
###                             35↓         40↓              50↓              60↓              70↓            7f↓
### input_len = 7   ---->   |-----xxxxxxx----|----------------|-----------picoC|TF{?????????????|????????????????|}---------------|...
### Using an initial input of 35 bytes is enough: decrementing until input_len = 7 we find all the bytes at the end of block [0x70,0x7f]

port = int(input("picoCTF port: "))
print()

known_block_start = "de is: picoCTF{"
flag = "picoCTF{"
print(f"{Style.RESET_ALL}PARTIAL FLAG: {Fore.GREEN}{Style.BRIGHT}", flag)
print()
print()
for input_len in range(35, 6, -1):
    chosen_input = "x"*input_len

    block_70_7f = send_recv_block(chosen_input, 7)
    last_char = ""
    for c in string.printable:
        test_input = "x"*11 + known_block_start + c
        print(f"{Style.RESET_ALL}TEST INPUT: {Fore.BLUE}{Style.BRIGHT}", test_input)
        block_40_4f = send_recv_block(test_input, 4)
        if are_equal(block_40_4f, block_70_7f):
            last_char = c
            flag += last_char
            print()
            print(f"{Style.RESET_ALL}PARTIAL FLAG: {Fore.GREEN}{Style.BRIGHT}", flag)
            print()
            print()
            break
    known_block_start = known_block_start[1:] + last_char

flag += "}"
print(f"{Style.RESET_ALL}{Style.BRIGHT}FLAG: {Fore.GREEN}", flag)
