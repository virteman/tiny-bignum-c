from building import *

cwd = GetCurrentDir()
src = Split('''
        bn.c
        tiny_rsa.c
        ''')
CPPPATH = [cwd]

group = DefineGroup('tiny-bignum-c', src, CPPPATH = CPPPATH)

Return('group')

