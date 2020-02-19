#!/usr/bin/env python
###
### Safe Stack Hash (EIP-based)
###

import sys,struct

class Triage( gdb.Command ):
    """
EIP-based triage: triage DEPTH
Construct a unique hash for a given program state.
    """
    def __init__( self ):
        gdb.Command.__init__( self, "triage", gdb.COMMAND_STACK )

    def invoke( self, args, from_tty ):
        depth = self.parse_args( args )
        frame = gdb.newest_frame()
        loopcnt = 0
        stacks = []
        while loopcnt < depth:
            loopcnt += 1
            try:
                pc = frame.pc()
                try:
                    ptrsize = struct.calcsize( "P" )
                    gdb.selected_inferior().read_memory( pc, ptrsize )
                    stacks.append( pc )
                except:
                    break
                # print "%x" % pc
                frame = frame.older()
            except:
                break

        with open('./hash.txt', 'w') as f:
            if len(stacks) > 0:
                f.write("|".join(map(lambda x: "%x" % x, stacks)))
            else:
                f.write("EMPTY")

    def parse_args( self, args ):
        try:
            return int( args.split( " " )[0] )
        except:
            return 5

Triage()