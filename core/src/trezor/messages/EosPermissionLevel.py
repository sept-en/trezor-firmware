# Automatically generated by pb2py
# fmt: off
import protobuf as p

if __debug__:
    try:
        from typing import Dict, List, Optional
        from typing_extensions import Literal
    except ImportError:
        Dict, List, Optional = None, None, None  # type: ignore


class EosPermissionLevel(p.MessageType):

    def __init__(
        self,
        actor: int = None,
        permission: int = None,
    ) -> None:
        self.actor = actor
        self.permission = permission

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('actor', p.UVarintType, 0),
            2: ('permission', p.UVarintType, 0),
        }
