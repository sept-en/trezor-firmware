# Automatically generated by pb2py
# fmt: off
import protobuf as p

if __debug__:
    try:
        from typing import Dict, List, Optional
        from typing_extensions import Literal  # noqa: F401
    except ImportError:
        Dict, List, Optional = None, None, None  # type: ignore


class TezosSignedTx(p.MessageType):
    MESSAGE_WIRE_TYPE = 153

    def __init__(
        self,
        signature: str = None,
        sig_op_contents: bytes = None,
        operation_hash: str = None,
    ) -> None:
        self.signature = signature
        self.sig_op_contents = sig_op_contents
        self.operation_hash = operation_hash

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('signature', p.UnicodeType, 0),
            2: ('sig_op_contents', p.BytesType, 0),
            3: ('operation_hash', p.UnicodeType, 0),
        }
