# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p

from .EosAsset import EosAsset

if __debug__:
    try:
        from typing import Dict, List, Optional
        from typing_extensions import Literal
    except ImportError:
        Dict, List, Optional = None, None, None  # type: ignore


class EosActionDelegate(p.MessageType):

    def __init__(
        self,
        sender: int = None,
        receiver: int = None,
        net_quantity: EosAsset = None,
        cpu_quantity: EosAsset = None,
        transfer: bool = None,
    ) -> None:
        self.sender = sender
        self.receiver = receiver
        self.net_quantity = net_quantity
        self.cpu_quantity = cpu_quantity
        self.transfer = transfer

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('sender', p.UVarintType, 0),
            2: ('receiver', p.UVarintType, 0),
            3: ('net_quantity', EosAsset, 0),
            4: ('cpu_quantity', EosAsset, 0),
            5: ('transfer', p.BoolType, 0),
        }
