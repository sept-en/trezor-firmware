# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p

if __debug__:
    try:
        from typing import Dict, List, Optional
        from typing_extensions import Literal
    except ImportError:
        Dict, List, Optional = None, None, None  # type: ignore


class MoneroLiveRefreshStepAck(p.MessageType):
    MESSAGE_WIRE_TYPE = 555

    def __init__(
        self,
        salt: bytes = None,
        key_image: bytes = None,
    ) -> None:
        self.salt = salt
        self.key_image = key_image

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('salt', p.BytesType, 0),
            2: ('key_image', p.BytesType, 0),
        }
