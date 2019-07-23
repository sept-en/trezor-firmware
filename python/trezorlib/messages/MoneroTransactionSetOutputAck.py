# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p

from .MoneroTransactionRsigData import MoneroTransactionRsigData

if __debug__:
    try:
        from typing import Dict, List, Optional
        from typing_extensions import Literal
    except ImportError:
        Dict, List, Optional = None, None, None  # type: ignore


class MoneroTransactionSetOutputAck(p.MessageType):
    MESSAGE_WIRE_TYPE = 512

    def __init__(
        self,
        tx_out: bytes = None,
        vouti_hmac: bytes = None,
        rsig_data: MoneroTransactionRsigData = None,
        out_pk: bytes = None,
        ecdh_info: bytes = None,
    ) -> None:
        self.tx_out = tx_out
        self.vouti_hmac = vouti_hmac
        self.rsig_data = rsig_data
        self.out_pk = out_pk
        self.ecdh_info = ecdh_info

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('tx_out', p.BytesType, 0),
            2: ('vouti_hmac', p.BytesType, 0),
            3: ('rsig_data', MoneroTransactionRsigData, 0),
            4: ('out_pk', p.BytesType, 0),
            5: ('ecdh_info', p.BytesType, 0),
        }
