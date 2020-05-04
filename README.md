# picoCTF2018 - SpyFi
## Text
> James Brahm, James Bond's less-franchised cousin, has left his secure communication with HQ running, but we couldn't find a way to steal his agent identification code. Can you? Conect with `nc 2018shell.picoctf.com 30399`. [Source](https://github.com/PrinceOfBorgo/picoCTF2018-SpyFi/blob/master/spy_terminal_no_flag.py).

Port may be different.

## Hints
> What mode is being used?

## Solution
TODO (see script comments)

## Usage
Simply run `SpyFi_attack.py` as a python script and insert port to which to connect:
```
$ python SpyFi_attack.py
picoCTF port: 30399

PARTIAL FLAG:  picoCTF{


TEST INPUT:  xxxxxxxxxxxde is: picoCTF{0
TEST INPUT:  xxxxxxxxxxxde is: picoCTF{1
TEST INPUT:  xxxxxxxxxxxde is: picoCTF{2
...
...
TEST INPUT:  xxxxxxxxxxx_c00l3$t_4884476
TEST INPUT:  xxxxxxxxxxx_c00l3$t_4884477

PARTIAL FLAG:  picoCTF{@g3nt6_1$_th3_c00l3$t_4884477


FLAG:  picoCTF{@g3nt6_1$_th3_c00l3$t_4884477}
```

