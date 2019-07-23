# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p

if __debug__:
    try:
        from typing import Dict, List, Optional
        from typing_extensions import Literal
    except ImportError:
        Dict, List, Optional = None, None, None  # type: ignore


class PassphraseRequest(p.MessageType):
    MESSAGE_WIRE_TYPE = 41

    def __init__(
        self,
        on_device: bool = None,
    ) -> None:
        self.on_device = on_device

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('on_device', p.BoolType, 0),
        }
