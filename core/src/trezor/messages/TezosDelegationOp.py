# Automatically generated by pb2py
# fmt: off
import protobuf as p

from .TezosContractID import TezosContractID

if __debug__:
    try:
        from typing import Dict, List, Optional
        from typing_extensions import Literal
    except ImportError:
        Dict, List, Optional = None, None, None  # type: ignore


class TezosDelegationOp(p.MessageType):

    def __init__(
        self,
        source: TezosContractID = None,
        fee: int = None,
        counter: int = None,
        gas_limit: int = None,
        storage_limit: int = None,
        delegate: bytes = None,
    ) -> None:
        self.source = source
        self.fee = fee
        self.counter = counter
        self.gas_limit = gas_limit
        self.storage_limit = storage_limit
        self.delegate = delegate

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('source', TezosContractID, 0),
            2: ('fee', p.UVarintType, 0),
            3: ('counter', p.UVarintType, 0),
            4: ('gas_limit', p.UVarintType, 0),
            5: ('storage_limit', p.UVarintType, 0),
            6: ('delegate', p.BytesType, 0),
        }
