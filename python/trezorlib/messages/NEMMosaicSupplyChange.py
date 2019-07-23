# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p

from . import NEMSupplyChangeType

if __debug__:
    try:
        from typing import Dict, List, Optional
        from typing_extensions import Literal
        EnumTypeNEMSupplyChangeType = Literal[None, 1, 2]
    except ImportError:
        Dict, List, Optional = None, None, None  # type: ignore
        EnumTypeNEMSupplyChangeType = None


class NEMMosaicSupplyChange(p.MessageType):

    def __init__(
        self,
        namespace: str = None,
        mosaic: str = None,
        type: EnumTypeNEMSupplyChangeType = None,
        delta: int = None,
    ) -> None:
        self.namespace = namespace
        self.mosaic = mosaic
        self.type = type
        self.delta = delta

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('namespace', p.UnicodeType, 0),
            2: ('mosaic', p.UnicodeType, 0),
            3: ('type', p.EnumType(NEMSupplyChangeType), 0),
            4: ('delta', p.UVarintType, 0),
        }
