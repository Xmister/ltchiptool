from abc import ABC
from logging import info
from typing import Optional

from ltchiptool import Family
from ltchiptool.models import OTAType
from ltchiptool.soc import SocInterfaceCommon

from .binary import BL60XBinary
from .flash import BL60XFlash


class BL60XMain(
    BL60XBinary,
    BL60XFlash,
    SocInterfaceCommon,
    ABC,
):
    """Serial reading and writing support for BL602/BL604."""

    def __init__(self, family: Family) -> None:
        super().__init__()
        self.family = family

    def hello(self):
        info("Hello from Bouffalo BL60x")

    @property
    def ota_type(self) -> Optional[OTAType]:
        return OTAType.DUAL
