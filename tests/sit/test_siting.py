# -*- encoding: utf-8 -*-
"""
tests.sit.test_siting module

"""

import pytest

from keri.core import NumDex, Number, DigDex, Diger
from keri.sit import (MaxHeight, MaxLimbLength, NodeSaidage, LeafSaidage,
                     Nodage, Leafage, Siter)
from keri.sit.siting import EmptyQb2, EmptyQb64

def test_siting_basic():
    """Basic Tests"""

    assert MaxHeight == 256
    assert MaxLimbLength == MaxHeight
    assert EmptyQb64 == '1AAP'
    assert EmptyQb2 == b'\xd4\x00\x0f'

    heighter = Number(num=256, code=NumDex.Short)
    assert heighter.qb64 == 'MAEA'
    assert heighter.qb2 == b'0\x01\x00'
    limber = Diger(raw=b'0'*32, code=DigDex.Blake3_256)
    assert limber.qb64 == 'EDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw'
    assert limber.qb2 == b'\x1000000000000000000000000000000000'

    nodage = Nodage(height=heighter.qb2, limb=limber.qb2)
    assert nodage._asdict() == {'height': b'0\x01\x00',
                                'limb': b'\x1000000000000000000000000000000000',
                                'left': b'\xd4\x00\x0f',
                                'right': b'\xd4\x00\x0f'}

    """Done Test"""

if __name__ == "__main__":
    test_siting_basic()

