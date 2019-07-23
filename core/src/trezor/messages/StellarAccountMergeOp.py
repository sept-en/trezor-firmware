# Automatically generated by pb2py
# fmt: off
import protobuf as p

if __debug__:
    try:
        from typing import Dict, List, Optional
        from typing_extensions import Literal
    except ImportError:
        Dict, List, Optional = None, None, None  # type: ignore


class StellarAccountMergeOp(p.MessageType):
    MESSAGE_WIRE_TYPE = 218

    def __init__(
        self,
        source_account: str = None,
        destination_account: str = None,
    ) -> None:
        self.source_account = source_account
        self.destination_account = destination_account

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('source_account', p.UnicodeType, 0),
            2: ('destination_account', p.UnicodeType, 0),
        }
