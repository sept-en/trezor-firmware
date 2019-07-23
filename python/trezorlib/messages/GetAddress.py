# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p

from . import InputScriptType
from .MultisigRedeemScriptType import MultisigRedeemScriptType

if __debug__:
    try:
        from typing import Dict, List, Optional
        from typing_extensions import Literal
        EnumTypeInputScriptType = Literal[None, 0, 1, 2, 3, 4]
    except ImportError:
        Dict, List, Optional = None, None, None  # type: ignore
        EnumTypeInputScriptType = None


class GetAddress(p.MessageType):
    MESSAGE_WIRE_TYPE = 29

    def __init__(
        self,
        address_n: List[int] = None,
        coin_name: str = None,
        show_display: bool = None,
        multisig: MultisigRedeemScriptType = None,
        script_type: EnumTypeInputScriptType = None,
    ) -> None:
        self.address_n = address_n if address_n is not None else []
        self.coin_name = coin_name
        self.show_display = show_display
        self.multisig = multisig
        self.script_type = script_type

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('address_n', p.UVarintType, p.FLAG_REPEATED),
            2: ('coin_name', p.UnicodeType, 0),  # default=Bitcoin
            3: ('show_display', p.BoolType, 0),
            4: ('multisig', MultisigRedeemScriptType, 0),
            5: ('script_type', p.EnumType(InputScriptType), 0),  # default=SPENDADDRESS
        }
