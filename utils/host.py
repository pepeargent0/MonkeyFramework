from typing import List

from dataclasses import dataclass


@dataclass
class Port:
    num: int
    ver: str

    def print(self):
        return f'port:' + str(self.num) + ' version:' + self.ver


@dataclass
class Host:
    ip: str
    mac: str
    ports: List[Port]
    os: str
