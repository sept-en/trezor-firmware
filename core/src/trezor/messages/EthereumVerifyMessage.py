# Automatically generated by pb2py
# fmt: off
import protobuf as p

if __debug__:
    try:
        from typing import Dict, List, Optional
        from typing_extensions import Literal
    except ImportError:
        Dict, List, Optional = None, None, None  # type: ignore


class EthereumVerifyMessage(p.MessageType):
    MESSAGE_WIRE_TYPE = 65

    def __init__(
        self,
        signature: bytes = None,
        message: bytes = None,
        address: str = None,
    ) -> None:
        self.signature = signature
        self.message = message
        self.address = address

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            2: ('signature', p.BytesType, 0),
            3: ('message', p.BytesType, 0),
            4: ('address', p.UnicodeType, 0),
        }
