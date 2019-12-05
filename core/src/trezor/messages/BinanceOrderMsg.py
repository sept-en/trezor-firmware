# Automatically generated by pb2py
# fmt: off
import protobuf as p

if __debug__:
    try:
        from typing import Dict, List  # noqa: F401
        from typing_extensions import Literal  # noqa: F401
        EnumTypeBinanceOrderType = Literal[0, 1, 2, 3]
        EnumTypeBinanceOrderSide = Literal[0, 1, 2]
        EnumTypeBinanceTimeInForce = Literal[0, 1, 2, 3]
    except ImportError:
        pass


class BinanceOrderMsg(p.MessageType):
    MESSAGE_WIRE_TYPE = 707

    def __init__(
        self,
        id: str = None,
        ordertype: EnumTypeBinanceOrderType = None,
        price: int = None,
        quantity: int = None,
        sender: str = None,
        side: EnumTypeBinanceOrderSide = None,
        symbol: str = None,
        timeinforce: EnumTypeBinanceTimeInForce = None,
    ) -> None:
        self.id = id
        self.ordertype = ordertype
        self.price = price
        self.quantity = quantity
        self.sender = sender
        self.side = side
        self.symbol = symbol
        self.timeinforce = timeinforce

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('id', p.UnicodeType, 0),
            2: ('ordertype', p.EnumType("BinanceOrderType", (0, 1, 2, 3)), 0),
            3: ('price', p.SVarintType, 0),
            4: ('quantity', p.SVarintType, 0),
            5: ('sender', p.UnicodeType, 0),
            6: ('side', p.EnumType("BinanceOrderSide", (0, 1, 2)), 0),
            7: ('symbol', p.UnicodeType, 0),
            8: ('timeinforce', p.EnumType("BinanceTimeInForce", (0, 1, 2, 3)), 0),
        }
