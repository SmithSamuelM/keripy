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
    # noncer = Noncer(nonce=None)  # creates random 16 bytes for nonce
    tuid = '0AAKbe-QRrZVxTMgs7gVAfp1'
    tuider = Noncer(nonce=tuid)
    assert tuider.nonce == tuid

    # node specific
    nverser = Verser(proto=Kiths.node, pvrsn=Version)
    assert nverser.qb64 == 'YnodeAAA'
    # per node
    nepther = Number(num=0)  # root
    assert nepther.qb64 == 'MAAA'
    nimber = Diger(raw=bytes(MaxDepthBytes), code=Siter.Code)
    assert nimber.qb64 == 'EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'



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

    # leaf specific
    lverser = Verser(proto=Kiths.leaf, pvrsn=Version)
    assert lverser.qb64 == 'YleafAAA'
    # per leaf
    lepther = Number(num=256)  # leaf
    assert lepther.qb64 == 'MAEA'
    infoer = Diger(ser=b"Leaf Info Here", code=DigDex.Blake2b_256) # not default SIT code
    assert infoer.qb64 == 'FAZi0qhemPCKISh8cvUK5z3iDHlcPsPz18SJCRHS0qnH'
    limber = Diger(ser=infoer.qb64b, code=Siter.Code)
    assert limber.qb64 == 'EKE_SPb9j35_FOnE649CPQfWNRYAq4JaklV-08uPpGP5'

    # create LeafSaidage and saidify with matter primitive instances
    saidage = LeafSaidage(version=lverser,
                             tuid=tuider,
                             said=Emptier, # placeholder
                             depth=lepther,
                             limb=limber)

    assert saidage._asdict() == \
    {
        'version': lverser,
        'tuid': tuider,
        'said': Emptier,
        'depth': lepther,
        'limb': limber
     }

    # replace saidage with SAIDed copy
    saidage = Siter.saidify(saidage=saidage)
    assert saidage.said.qb64 == 'EG4CbOPT7FuQ8D5Q6a4JFzsrJBSP3NwPjjlWgKmcwZKS'
    dqb64 = {l: v.qb64 for l, v in saidage._asdict().items()}
    assert dqb64 == \
    {
        'version': 'YleafAAA',
        'tuid': '0AAKbe-QRrZVxTMgs7gVAfp1',
        'said': 'EG4CbOPT7FuQ8D5Q6a4JFzsrJBSP3NwPjjlWgKmcwZKS',
        'depth': 'MAEA',
        'limb': 'EKE_SPb9j35_FOnE649CPQfWNRYAq4JaklV-08uPpGP5',
    }

    # create leafage with qb2 values
    leafage = Leafage(depth=saidage.depth.qb2,
                      limb=saidage.limb.qb2)

    assert leafage._asdict() == \
    {
        'depth': b'0\x01\x00',
        'limb': b'\x10\xa1?H\xf6\xfd\x8f~\x7f\x14\xe9\xc4\xeb\x8fB=\x07\xd65\x16'
                b'\x00\xab\x82Z\x92U~\xd3\xcb\x8f\xa4c\xf9',
    }

    # create leaf Partage of leafage with qb2 values
    leaf = Partage(said=saidage.said.qb2, part=leafage)
    assert leaf._asdict() == \
    {
        'said': b'\x10n\x02l\xe3\xd3\xec[\x90\xf0>P\xe9\xae\t\x17;+$\x14'
                b'\x8f\xdc\xdc\x0f\x8e9V\x80\xa9\x9c\xc1\x92\x92',
        'part': Leafage(depth=b'0\x01\x00',
                        limb=b'\x10\xa1?H\xf6\xfd\x8f~\x7f\x14\xe9\xc4\xeb\x8fB=\x07\xd65\x16\x00\xab\x82Z\x92U~\xd3\xcb\x8f\xa4c\xf9')
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
    assert siter.rootage
    assert siter.root
    assert len(siter.nodes) == 1
    assert siter.leaves == {}
    assert siter.infos == {}

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

    assert siter.root.said.qb64 == 'EPWZ53lTK7o5oyC6cM2duB5vhNXRAFthkSndZQO4vArf'
    assert siter.root.part.depth.num == 0
    assert siter.root.part.limb.qb64 == 'EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    assert siter.root.part.left.nonce == ""
    assert siter.root.part.right.nonce == ""

    assert siter.nodes == \
    {
        siter.root.said.qb2: siter.rootage,
    }
    assert siter.leaves == {}
    assert siter.infos == {}


    # test insert
    sn = 0
    info = f"Leaf Info {sn:x}"
    leafer = Diger(ser=info.encode(), code=DigDex.Blake2b_256) # not default SIT code
    assert leafer.qb64 == 'FBQuXQPYcNMz3S1I6Ye6ByGd_R1VJkLcllZ92Au5JUK4'

    result = siter.insert(leafer=leafer)
    assert result is None



    """Done Test"""

if __name__ == "__main__":
    test_siting_siter_class()
    test_siter_basic()
