#!/usr/bin/env python
# -*- coding: utf-8 -*-


from __future__ import print_function

import os
import sys

from debug import call_inspector, structure_inspector
from params import parameters
from params.parameters import parse_args, get_modules_to_import
from params.writter import write_in_files
import cnerator


def run(args):
    # Sets the recursion limit
    sys.setrecursionlimit(args.recursion)

    # return_instrumentator.monkey_path()
    # program = cnerator.generators.generate_program()

    ###
    # 3k (ALL - NORMAL)
    ###
    # program = cnerator.generators.generate_program_with_distribution({
    #     "v_functions": {"total": 300, "condition": lambda f: isinstance(f.return_type, cnerator.ast.Void)},
    #     "b_functions": {"total": 300, "condition": lambda f: isinstance(f.return_type, cnerator.ast.Bool)},
    #     "sc_functions": {"total": 300, "condition": lambda f: isinstance(f.return_type, cnerator.ast.SignedChar)},
    #     "sSi_functions": {"total": 300, "condition": lambda f: isinstance(f.return_type, cnerator.ast.SignedShortInt)},
    #     "si_functions": {"total": 300, "condition": lambda f: isinstance(f.return_type, cnerator.ast.SignedInt)},
    #     "sLLi_functions": {"total": 300, "condition": lambda f: isinstance(f.return_type, cnerator.ast.SignedLongLongInt)},
    #     "f_functions": {"total": 300, "condition": lambda f: isinstance(f.return_type, cnerator.ast.Float)},
    #     "d_functions": {"total": 300, "condition": lambda f: isinstance(f.return_type, cnerator.ast.Double)},
    #     "p_functions": {"total": 300, "condition": lambda f: isinstance(f.return_type, cnerator.ast.Pointer)},
    #     "struct_functions": {"total": 300, "condition": lambda f: isinstance(f.return_type, cnerator.ast.Struct)},
    # }, 300*10, remove_outsiders=True)

    ###
    # 0.15k (ALL - SNOWMAN)
    ###
    # program = cnerator.generators.generate_program_with_distribution({
    #     "v_functions": {"total": 15, "condition": lambda f: isinstance(f.return_type, cnerator.ast.Void)},
    #     "b_functions": {"total": 15, "condition": lambda f: isinstance(f.return_type, cnerator.ast.Bool)},
    #     "sc_functions": {"total": 15, "condition": lambda f: isinstance(f.return_type, cnerator.ast.SignedChar)},
    #     "sSi_functions": {"total": 15, "condition": lambda f: isinstance(f.return_type, cnerator.ast.SignedShortInt)},
    #     "si_functions": {"total": 15, "condition": lambda f: isinstance(f.return_type, cnerator.ast.SignedInt)},
    #     "sLLi_functions": {"total": 15, "condition": lambda f: isinstance(f.return_type, cnerator.ast.SignedLongLongInt)},
    #     "f_functions": {"total": 15, "condition": lambda f: isinstance(f.return_type, cnerator.ast.Float)},
    #     "d_functions": {"total": 15, "condition": lambda f: isinstance(f.return_type, cnerator.ast.Double)},
    #     "p_functions": {"total": 15, "condition": lambda f: isinstance(f.return_type, cnerator.ast.Pointer)},
    #     "struct_functions": {"total": 15, "condition": lambda f: isinstance(f.return_type, cnerator.ast.Struct)},
    # }, 15*10, remove_outsiders=True)

    ###
    # FUNCTION vs PROCEDURE, 4k functions
    ###
    # program = cnerator.generators.generate_program_with_distribution({
    #     "procedures": {"total": 2000, "condition": lambda f: f.return_type == cnerator.ast.Void()},
    #     "functions":  {"total": 2000, "condition": lambda f: f.return_type != cnerator.ast.Void()},
    # }, 4000, remove_outsiders=False)

    ###
    # 3k (SIZE - NORMAL)
    ###
    # program = cnerator.generators.generate_program_with_distribution({
    #     "v_functions": {"total": 429, "condition": lambda f: isinstance(f.return_type, cnerator.ast.Void)},
    #     "b_functions": {"total": 215, "condition": lambda f: isinstance(f.return_type, cnerator.ast.Bool)},
    #     "sc_functions": {"total": 214, "condition": lambda f: isinstance(f.return_type, cnerator.ast.SignedChar)},
    #     "sSi_functions": {"total": 428, "condition": lambda f: isinstance(f.return_type, cnerator.ast.SignedShortInt)},
    #     "si_functions": {"total": 142, "condition": lambda f: isinstance(f.return_type, cnerator.ast.SignedInt)},
    #     "sLLi_functions": {"total": 428, "condition": lambda f: isinstance(f.return_type, cnerator.ast.SignedLongLongInt)},
    #     "f_functions": {"total": 429, "condition": lambda f: isinstance(f.return_type, cnerator.ast.Float)},
    #     "d_functions": {"total": 429, "condition": lambda f: isinstance(f.return_type, cnerator.ast.Double)},
    #     "p_functions": {"total": 143, "condition": lambda f: isinstance(f.return_type, cnerator.ast.Pointer)},
    #     "struct_functions": {"total": 143, "condition": lambda f: isinstance(f.return_type, cnerator.ast.Struct)},
    # }, 3000, remove_outsiders=True)

    ###
    # 0.15k (SIZE - SNOWMAN)
    ###
    # program = cnerator.generators.generate_program_with_distribution({
    #     "v_functions": {"total": 22, "condition": lambda f: isinstance(f.return_type, cnerator.ast.Void)},
    #     "b_functions": {"total": 11, "condition": lambda f: isinstance(f.return_type, cnerator.ast.Bool)},
    #     "sc_functions": {"total": 10, "condition": lambda f: isinstance(f.return_type, cnerator.ast.SignedChar)},
    #     "sSi_functions": {"total": 21, "condition": lambda f: isinstance(f.return_type, cnerator.ast.SignedShortInt)},
    #     "si_functions": {"total": 7, "condition": lambda f: isinstance(f.return_type, cnerator.ast.SignedInt)},
    #     "sLLi_functions": {"total": 21, "condition": lambda f: isinstance(f.return_type, cnerator.ast.SignedLongLongInt)},
    #     "f_functions": {"total": 22, "condition": lambda f: isinstance(f.return_type, cnerator.ast.Float)},
    #     "d_functions": {"total": 22, "condition": lambda f: isinstance(f.return_type, cnerator.ast.Double)},
    #     "p_functions": {"total": 7, "condition": lambda f: isinstance(f.return_type, cnerator.ast.Pointer)},
    #     "struct_functions": {"total": 7, "condition": lambda f: isinstance(f.return_type, cnerator.ast.Struct)},
    # }, 150, remove_outsiders=True)

    ###
    # 10 (SIZE - NORMAL)
    ###
    """
    program = cnerator.generators.generate_program_with_function_distribution({
        "v_functions": {"total": 1, "condition": lambda f: isinstance(f.return_type, cnerator.ast.Void)},
        "b_functions": {"total": 1, "condition": lambda f: isinstance(f.return_type, cnerator.ast.Bool)},
        "sc_functions": {"total": 1, "condition": lambda f: isinstance(f.return_type, cnerator.ast.SignedChar)},
        "sSi_functions": {"total": 1, "condition": lambda f: isinstance(f.return_type, cnerator.ast.SignedShortInt)},
        "si_functions": {"total": 1, "condition": lambda f: isinstance(f.return_type, cnerator.ast.SignedInt)},
        "sLLi_functions": {"total": 1, "condition": lambda f: isinstance(f.return_type, cnerator.ast.SignedLongLongInt)},
        "f_functions": {"total": 1, "condition": lambda f: isinstance(f.return_type, cnerator.ast.Float)},
        "d_functions": {"total": 1, "condition": lambda f: isinstance(f.return_type, cnerator.ast.Double)},
        "p_functions": {"total": 1, "condition": lambda f: isinstance(f.return_type, cnerator.ast.Pointer)},
        "struct_functions": {"total": 1, "condition": lambda f: isinstance(f.return_type, cnerator.ast.Struct)},
    }, args, 10, remove_unwanted_functions=True)
    """

    if args.functions:  # if a json file was passed, it defines the functions to be generated
        dictionary = parameters.parse_function_specification_json_file(args.functions)
        program = cnerator.generators.generate_program_with_function_distribution(dictionary, args, remove_unwanted_functions=True)
    else:  # otherwise, a random program is generated, considering the specified probabilities
        program = cnerator.generators.generate_program()

    #  Load all the visitor modules and run them, in the same order
    modules = get_modules_to_import(args.visitors)
    for module in modules:
        module.visit(program)

    # Create output directory
    if not os.path.isdir(args.output_dir):
        os.mkdir(args.output_dir)

    # Write code to files
    write_in_files(program, args)

    if args.debug:
        # Write structure graph
        structure_inspector.write_graph(program, os.path.join(args.output_dir, args.output + ".structure.dot"))
        # Write call graph
        call_inspector.write_graph(program, True, os.path.join(args.output_dir, args.output + ".call.dot"))
        call_inspector.write_graph(program, False, os.path.join(args.output_dir, args.output + ".call_light.dot"))


def main():
    exit(run(parse_args()))


if __name__ == "__main__":
    main()


