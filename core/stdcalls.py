from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Tuple
from core import ast, probs_helper
from itertools import count


class StandardCall(ABC):
    """Base class for invocation of function from standard lib"""

    default_args = iter("arg_" + str(c) for c in count())

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
    def return_type(self) -> ast.Type:
        """Return type of function"""

    @property
    @abstractmethod
    def arg_types(self) -> List[ast.Type]:
        """Return type of function"""

    @property
    def param_types(self) -> List[Tuple[str, ast.Type]]:
        """Parameter types of function"""
        return list(zip(self.default_args, self.arg_types))

    def __repr__(self) -> str:
        return f"{self.return_type} {self.name}({', '.join(str(p) for p in self.param_types)});"


class StandardCallInvocation:
    """factory based on probabilities"""


class Strlen(StandardCall):
    """size_t strlen(char*)"""

    lib = "string.h"
    name = "strlen"
    return_type = ast.UnsignedInt()
    arg_types = [ast.Pointer(ast.UnsignedChar())]
