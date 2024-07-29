from cle.backends import Blob, register_backend
from archinfo import arch_from_id

import re
import logging

l = logging.getLogger("cle.blob")

__all__ = ('Yan',)

class Yan(Blob):
    is_default = True

    def __init__(self, *args, offset=0, **kwargs):
        super(Yan, self).__init__(*args,
                arch=arch_from_id('Yan85'),
                offset=offset,
                entry_point=0,
                **kwargs)
        self.os = "Yan85"

register_backend('Yan85', Yan)
