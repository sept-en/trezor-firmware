# Automatically generated by pb2py
# fmt: off
import protobuf as p

if __debug__:
    try:
        from typing import Dict, List, Optional
        from typing_extensions import Literal
    except ImportError:
        Dict, List, Optional = None, None, None  # type: ignore


class LiskPublicKey(p.MessageType):
    MESSAGE_WIRE_TYPE = 122

    def __init__(
        self,
        public_key: bytes = None,
    ) -> None:
        self.public_key = public_key

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('public_key', p.BytesType, 0),
        }
