# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p

if __debug__:
    try:
        from typing import Dict, List, Optional
        from typing_extensions import Literal
    except ImportError:
        Dict, List, Optional = None, None, None  # type: ignore


class StellarAssetType(p.MessageType):

    def __init__(
        self,
        type: int = None,
        code: str = None,
        issuer: str = None,
    ) -> None:
        self.type = type
        self.code = code
        self.issuer = issuer

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('type', p.UVarintType, 0),
            2: ('code', p.UnicodeType, 0),
            3: ('issuer', p.UnicodeType, 0),
        }
