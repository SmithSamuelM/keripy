# -*- encoding: utf-8 -*-
"""
tests.sit.test_siting module

"""

import pytest
from keri import Versionage
from keri.core import NumDex, Number, DigDex, Diger, Noncer, Verser
from keri.sit import (Version, MaxDepth, MaxDepthBytes, Kithage, Kiths,
                      NodeSaidage, Nodage, LeafSaidage, Leafage, Partage,
                      Siter)
from keri.sit.siting import Emptier, EmptyQb2, EmptyQb64

def test_siting_siter_class():
    """Test of siting module and siter class methods"""

    assert Version == Versionage(0, 0)
    assert MaxDepth == 256
    assert MaxDepthBytes == 32
    assert MaxDepth == 2 ** 3 * MaxDepthBytes
    assert isinstance(Kiths, Kithage)
    assert Kiths._asdict() == {'node': 'node', 'leaf': 'leaf'}

    assert EmptyQb64 == '1AAP'
    assert EmptyQb2 == b'\xd4\x00\x0f'

    assert Siter.Code == DigDex.Blake3_256
    assert Siter.Dummy == b'#'

    # test saidify
    nverser = Verser(proto=Kiths.node, pvrsn=Version)
    assert nverser.qb64 == 'YnodeAAA'
    # noncer = Noncer(nonce=None)  # creates random 16 bytes for nonce
    tuid = '0AAKbe-QRrZVxTMgs7gVAfp1'
    tuider = Noncer(nonce=tuid)
    assert tuider.nonce == tuid
    nepther = Number(num=0)  # root
    assert nepther.qb64 == 'MAAA'
    nimber = Diger(raw=bytes(MaxDepthBytes), code=Siter.Code)
    assert nimber.qb64 == 'EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    lverser = Verser(proto=Kiths.leaf, pvrsn=Version)
    assert lverser.qb64 == 'YleafAAA'
    lepther = Number(num=256)  # leaf
    assert lepther.qb64 == 'MAEA'
    lnum = 1 # branch path ends with 1
    limber = Diger(raw=lnum.to_bytes(length=MaxDepthBytes), code=Siter.Code)
    assert limber.qb64 == 'EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB'
    infoer = Diger(ser=b"Leaf Info Here", code=DigDex.Blake2b_256) # not default SIT code
    assert infoer.qb64 == 'FAZi0qhemPCKISh8cvUK5z3iDHlcPsPz18SJCRHS0qnH'

    # create NodeSaidage and saidify with matter primitive instances
    saidage = NodeSaidage(version=nverser,
                             tuid=tuider,
                             said=Emptier, # placeholder
                             depth=nepther,
                             limb=nimber,
                             left=Emptier,
                             right=Emptier)

    assert saidage._asdict() == \
    {
        'version': nverser,
        'tuid': tuider,
        'said': Emptier,
        'depth': nepther,
        'limb': nimber,
        'left': Emptier,
        'right': Emptier,
     }

    # replace saidage with SAIDed copy
    saidage = Siter.saidify(saidage=saidage)
    assert saidage.said.qb64 == 'ENUNJwkeHIGl3X8k5Adslk1RUUUChJqg4pT8xigvWL0F'
    dqb64 = {l: v.qb64 for l, v in saidage._asdict().items()}
    assert dqb64 == \
    {
        'version': 'YnodeAAA',
        'tuid': '0AAKbe-QRrZVxTMgs7gVAfp1',
        'said': 'ENUNJwkeHIGl3X8k5Adslk1RUUUChJqg4pT8xigvWL0F',
        'depth': 'MAAA',
        'limb': 'EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        'left': '1AAP',
        'right': '1AAP'
    }

    # create nodage with qb2 values
    nodage = Nodage(depth=saidage.depth.qb2,
                    limb=saidage.limb.qb2,
                    left=saidage.left.qb2,
                    right=saidage.right.qb2)


    assert nodage._asdict() == \
    {
        'depth': b'0\x00\x00',
        'limb': b'\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                b'\x00',
         'left': b'\xd4\x00\x0f',
         'right': b'\xd4\x00\x0f'
    }

    # create node Partage of nodage with qb2 values
    node = Partage(said=saidage.said.qb2, part=nodage)
    assert node._asdict() == \
    {
        'said': b"\x10\xd5\r'\t\x1e\x1c\x81\xa5\xdd\x7f$\xe4\x07l\x96MQQE"
                b'\x02\x84\x9a\xa0\xe2\x94\xfc\xc6(/X\xbd\x05',
        'part': Nodage(depth=b'0\x00\x00',
                       limb=b'\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
                       left=b'\xd4\x00\x0f',
                       right=b'\xd4\x00\x0f')
    }


    # create LeafSaidage and saidify with matter primitive instances
    saidage = LeafSaidage(version=lverser,
                             tuid=tuider,
                             said=Emptier, # placeholder
                             depth=lepther,
                             limb=limber,
                             info=infoer)

    assert saidage._asdict() == \
    {
        'version': lverser,
        'tuid': tuider,
        'said': Emptier,
        'depth': lepther,
        'limb': limber,
        'info': infoer,
     }

    # replace saidage with SAIDed copy
    saidage = Siter.saidify(saidage=saidage)
    assert saidage.said.qb64 == 'EDZUClMaG_NGyNuvV8-G7Q6Uxjuw1la5b2vr0Lu8TDcM'
    dqb64 = {l: v.qb64 for l, v in saidage._asdict().items()}
    assert dqb64 == \
    {
        'version': 'YleafAAA',
        'tuid': '0AAKbe-QRrZVxTMgs7gVAfp1',
        'said': 'EDZUClMaG_NGyNuvV8-G7Q6Uxjuw1la5b2vr0Lu8TDcM',
        'depth': 'MAEA',
        'limb': 'EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB',
        'info': 'FAZi0qhemPCKISh8cvUK5z3iDHlcPsPz18SJCRHS0qnH'
    }

    # create leafage with qb2 values
    leafage = Leafage(depth=saidage.depth.qb2,
                    limb=saidage.limb.qb2,
                    info=saidage.info.qb2)

    assert leafage._asdict() == \
    {
        'depth': b'0\x01\x00',
        'limb': b'\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                b'\x01',
        'info': b'\x14\x06b\xd2\xa8^\x98\xf0\x8a!(|r\xf5\n\xe7=\xe2\x0cy\\>\xc3\xf3'
                b'\xd7\xc4\x89\t\x11\xd2\xd2\xa9\xc7'}

    # create leaf Partage of leafage with qb2 values
    leaf = Partage(said=saidage.said.qb2, part=leafage)
    assert leaf._asdict() == \
    {
        'said': b'\x106T\nS\x1a\x1b\xf3F\xc8\xdb\xafW\xcf\x86\xed\x0e\x94\xc6;'
                b'\xb0\xd6V\xb9ok\xeb\xd0\xbb\xbcL7\x0c',
        'part': Leafage(depth=b'0\x01\x00',
                        limb=b'\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01',
                        info=b'\x14\x06b\xd2\xa8^\x98\xf0\x8a!(|r\xf5\n\xe7=\xe2\x0cy\\>\xc3\xf3\xd7\xc4\x89\t\x11\xd2\xd2\xa9\xc7')
    }


    """Done Test"""

def test_siter_basic():
    """Test basic siter instance creation and methods"""
    siter = Siter()  # default Siter
    assert siter.svrsn == Version
    assert len(siter.tuider.qb64) == 24  # random tuid
    assert siter.code == DigDex.Blake3_256
    assert siter.nodeVerser.qb64 == 'YnodeAAA'
    assert siter.leafVerser.qb64 == 'YleafAAA'
    assert len(siter.nodes) == 1
    assert len(siter.leaves) == 0

    tuid = '0ACiicCYoKAqao8qDdnlFVrY'
    siter = Siter(tuid=tuid)  # Siter with known tuid
    assert siter.svrsn == Version
    assert siter.tuider.qb64 == tuid
    assert siter.code == DigDex.Blake3_256
    assert siter.nodeVerser.qb64 == 'YnodeAAA'
    assert siter.leafVerser.qb64 == 'YleafAAA'
    assert siter.rootage == Nodage(depth=b'0\x00\x00',
                                   limb=b'\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
                                   left=b'\xd4\x00\x0f',
                                   right=b'\xd4\x00\x0f')

    assert siter.root == Partage(said=b'\x10\xf5\x99\xe7yS+\xba9\xa3 \xbap\xcd\x9d\xb8\x1eo\x84\xd5\xd1\x00[a\x91)\xdde\x03\xb8\xbc\n\xdf',
                                 part=Nodage(depth=b'0\x00\x00',
                                             limb=b'\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
                                             left=b'\xd4\x00\x0f',
                                             right=b'\xd4\x00\x0f'))

    assert siter.nodes == \
    {
        siter.root.said: siter.root.part,
    }
    assert siter.leaves == {}


    """Done Test"""

if __name__ == "__main__":
    test_siting_siter_class()
    test_siter_basic()
