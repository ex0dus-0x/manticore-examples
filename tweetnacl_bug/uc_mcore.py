#!/usr/bin/env python3
"""
uc_mcore.py

    1. Generate parse tree of helper functions
    called by target function.
    Contain: funcname, argtypes, rtype

    2. During SE run, symbolicate func arguments
    for target function.

    3. Attach hooks to helper functions for concrete
    execution through FFI

"""
import os.path
import argparse

from manticore.core.smtlib import operators
from manticore.native import Manticore
from manticore.native.cpu import abstractcpu

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-b", "--binary", dest="binary", required=True,
                        help="Target ELF binary for symbolic execution")
    parser.add_argument("-s", "--symbol", dest="symbol", required=True,
                        help="Function symbol for equivalence analysis")
    parser.add_argument("-t", "--trace", action='store_true', required=False,
                        help="Set to execute instruction recording")
    parser.add_argument("-v", "--verbosity", dest="verbosity", required=False,
                        default=2, help="Set verbosity for Manticore")

    # parse or print help
    args = parser.parse_args()
    if args is None:
        parser.print_help()
    
    # initialize Manticore
    m = Manticore(args.binary)
    m.context['trace'] = []
    m.context['sym'] = ""
    m.context['funcs'] = {}


    with m.locked_context() as context:
        # generate parse tree for functions in source
        context['funcs'] = generate_parse_tree(args.binary + ".c", context['sym'])

        # save symbol and resolve it for address
        context['sym'] = args.symbol 
        sym_addr = m.resolve(context['sym'])

 
    # add record trace hook throughout execution if specified by user 
    if args.trace:
        @m.hook(None)
        def record(state):
            pc = state.cpu.PC
            print(f"{hex(pc)}"),
            with m.locked_context() as context:
                context['trace'] += [pc]


    # we don't care about any other execution except at the specified function,
    # so once we finish in _start and enter main, skip to our symbol's address.
    @m.hook(m.resolve('main'))
    def skip_main(state):
        print(f"Skipping execution! Jumping to {args.symbol}")
        state.cpu.EIP = sym_addr


    # at target symbol, assuming target was compiled for x86_64 
    # we immediately symbolicate the arguments. The calling convention
    # looks as so:
    # arg1: rdi, arg2: rsi, arg3: rdx
    @m.hook(sym_addr)
    def sym(state):
        """ create symbolic args with RSI and RDI
        to perform SE on function """

        print("Injecting symbolic buffer into args")

        # create symbolic buffers
        rdi_buf = state.new_symbolic_buffer(32, label='arg1')
        rsi_buf = state.new_symbolic_buffer(32, label='arg2')
        
        # apply constraints
        for i in range(32):
            state.constrain(operators.AND(ord(' ') <= rdi_buf[i], rdi_buf[i] <= ord('}')))
            state.constrain(operators.AND(ord(' ') <= rdi_buf[i], rdi_buf[i] <= ord('}')))
        
        with m.locked_context() as context:
            
            # load addresses into context
            #context['rdi'] = state.cpu.RDI
            context['rsi'] = state.cpu.RSI

            # write bytes
            #state.cpu.write_bytes(context['rdi'], rdi_buf)
            state.cpu.write_bytes(context['rsi'], rsi_buf)


    # run manticore
    m.verbosity(args.verbosity)
    m.run()
    print(f"Total instructions: {len(m.context['trace'])}\nLast instruction: {hex(m.context['trace'][-1])}")


if __name__ == "__main__":
    main()
