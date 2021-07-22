from abc import ABC, abstractmethod
from collections import defaultdict
from typing import Iterable, List, Optional, Tuple
from core import ast, probs_helper
from core.ast import Program, Function, ASTNode
from itertools import count
from random import choice


class StandardCall(ABC):
    """Base class for invocation of function from standard lib"""

    DEFAULT_ARGS = iter("arg_" + str(c) for c in count())

    @property
    @abstractmethod
    def lib(self) -> str:
        """Name of library containing function"""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of function"""

    @property
    @abstractmethod
    def has_side_effect(self) -> bool:
        """True if function has side effect, meaning it can be called in simple
        statement and not be deleted by compiler optimization"""

    @property
    @abstractmethod
    def return_type(self) -> ast.Type:
        """Return type of function"""

    @property
    @abstractmethod
    def arg_types(self) -> List[ast.Type]:
        """Argument types of function"""

    @property
    @abstractmethod
    def arg_names(self) -> Optional[Iterable[str]]:
        """Argument names of function"""

    @property
    def param_types(self) -> List[Tuple[str, ast.Type]]:
        """Parameter names with types of function"""
        arg_names = self.arg_names if self.arg_names else self.DEFAULT_ARGS
        return list(zip(arg_names, self.arg_types))

    def __repr__(self) -> str:
        args = ", ".join(
            f"{arg_type} {arg_name}" for arg_name, arg_type in self.param_types
        )
        return f"{self.return_type} {self.name}({args});"


class Strlen(StandardCall):
    """size_t strlen(char*)"""

    lib = "string.h"
    name = "strlen"
    return_type = ast.UnsignedInt()
    arg_types = [ast.Pointer(ast.UnsignedChar())]
    arg_names = None
    has_side_effect = False


class Memset(StandardCall):
    """void* memset(void*, int, size_t)"""

    lib = "string.h"
    name = "memset"
    return_type = ast.Pointer(ast.UnsignedInt())
    arg_types = [ast.Pointer(ast.UnsignedInt()), ast.SignedInt(), ast.UnsignedInt()]
    arg_names = None
    has_side_effect = True


class Memcpy(StandardCall):
    """size_t strlen(char*)"""

    lib = "string.h"
    name = "memcpy"
    return_type = ast.Pointer(ast.UnsignedInt())
    arg_types = [
        ast.Pointer(ast.UnsignedInt()),
        ast.Pointer(ast.UnsignedInt()),
        ast.UnsignedInt(),
    ]
    arg_names = None
    has_side_effect = True


methods = StandardCall.__subclasses__()
methods_by_return_type = defaultdict(list)
methods_with_side_effects = [method for method in methods if method.has_side_effect]
for method in methods:
    methods_by_return_type[method.return_type].append(method)


def get_std_method_by_return_type(return_type):
    candidates = methods_by_return_type[return_type]
    if not candidates:
        print("no method for given return type")
        return None
    std_method = choice(candidates)
    return std_method()


def get_std_method_with_side_effects():
    if not methods_with_side_effects:
        print("no std methods with side effects")
        return None
    std_method = choice(methods_with_side_effects)
    return std_method()


def get_std_method():
    if not methods_with_side_effects:
        print("no std methods")
        return None
    std_method = choice(methods)
    return std_method()
