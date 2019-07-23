# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p

if __debug__:
    try:
        from typing import Dict, List, Optional
        from typing_extensions import Literal
    except ImportError:
        Dict, List, Optional = None, None, None  # type: ignore


class MoneroGetWatchKey(p.MessageType):
    MESSAGE_WIRE_TYPE = 542

    def __init__(
        self,
        address_n: List[int] = None,
        network_type: int = None,
    ) -> None:
        self.address_n = address_n if address_n is not None else []
        self.network_type = network_type

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('address_n', p.UVarintType, p.FLAG_REPEATED),
            2: ('network_type', p.UVarintType, 0),
        }
