# Automatically generated by pb2py
# fmt: off
import protobuf as p

from . import PassphraseSourceType

if __debug__:
    try:
        from typing import Dict, List, Optional
        from typing_extensions import Literal
        EnumTypePassphraseSourceType = Literal[None, 0, 1, 2]
    except ImportError:
        Dict, List, Optional = None, None, None  # type: ignore
        EnumTypePassphraseSourceType = None


class ApplySettings(p.MessageType):
    MESSAGE_WIRE_TYPE = 25

    def __init__(
        self,
        language: str = None,
        label: str = None,
        use_passphrase: bool = None,
        homescreen: bytes = None,
        passphrase_source: EnumTypePassphraseSourceType = None,
        auto_lock_delay_ms: int = None,
        display_rotation: int = None,
    ) -> None:
        self.language = language
        self.label = label
        self.use_passphrase = use_passphrase
        self.homescreen = homescreen
        self.passphrase_source = passphrase_source
        self.auto_lock_delay_ms = auto_lock_delay_ms
        self.display_rotation = display_rotation

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('language', p.UnicodeType, 0),
            2: ('label', p.UnicodeType, 0),
            3: ('use_passphrase', p.BoolType, 0),
            4: ('homescreen', p.BytesType, 0),
            5: ('passphrase_source', p.EnumType(PassphraseSourceType), 0),
            6: ('auto_lock_delay_ms', p.UVarintType, 0),
            7: ('display_rotation', p.UVarintType, 0),
        }
