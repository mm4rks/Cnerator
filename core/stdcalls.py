from dataclasses import dataclass
from core import ast


@dataclass
class strlen:
    lib: str = "stdlib"
    return_type: str = ""

    @property
    def include(self):
        return f"#include {self.lib}"
