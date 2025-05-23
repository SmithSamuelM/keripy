# -*- coding: utf-8 -*-
"""
tests.core.test_structing module

"""
from dataclasses import dataclass, astuple, asdict
from typing import NamedTuple
from collections import namedtuple
from collections.abc import Mapping


import pytest


from keri import kering

from keri.help import helping

from keri.core import (Matter, Diger, Prefixer, Number, Verser)


from keri.core import structing
from keri.core.structing import (SealDigest, SealRoot, SealBack, SealEvent,
                                 SealLast, SealTrans, SealKind)
from keri.core.structing import (Castage,
                                 Structor, EClanDom, ECastDom,
                                 Sealer, SClanDom, SCastDom, )


def test_structor_doms():
    """
    test doms in structure
    """
    assert EClanDom == structing.EmptyClanDom()
    assert ECastDom == structing.EmptyCastDom()
    assert SClanDom == structing.SealClanDom()
    assert SCastDom == structing.SealCastDom()

    assert asdict(EClanDom) == {}
    assert asdict(ECastDom) == {}

    assert asdict(SClanDom) == \
    {
        'SealDigest': SealDigest,
        'SealRoot': SealRoot,
        'SealEvent': SealEvent,
        'SealTrans': SealTrans,
        'SealLast': SealLast,
        'SealBack': SealBack,
        'SealKind': SealKind,
    }

    assert asdict(SCastDom) == \
    {
        'SealDigest': SealDigest(d=Castage(kls=Diger, prm=None)),
        'SealRoot': SealRoot(rd=Castage(kls=Diger, prm=None)),
        'SealEvent': SealEvent(i=Castage(kls=Prefixer, prm=None),
                               s=Castage(kls=Number, prm='numh'),
                               d=Castage(kls=Diger, prm=None)),
        'SealTrans': SealTrans(s=Castage(kls=Number, prm='numh'),
                               d=Castage(kls=Diger, prm=None)),
        'SealLast': SealLast(i=Castage(kls=Prefixer, prm=None)),
        'SealBack': SealBack(bi=Castage(kls=Prefixer, prm=None),
                                 d=Castage(kls=Diger, prm=None)),
        'SealKind': SealKind(t=Castage(kls=Verser, prm=None),
                                 d=Castage(kls=Diger, prm=None)),
    }


    """End Test"""



def test_structor_class():
    """
    test Structor class variables etc
    """
    assert Structor.Clans == EClanDom
    assert Structor.Casts == ECastDom
    assert Structor.Names == {}

    """End Test"""

def test_structor():
    """
    test Structor instance
    """

    with pytest.raises(kering.InvalidValueError):
        structor = Structor()  # test default


    aid = 'BN5Lu0RqptmJC-iXEldMMrlEew7Q01te2fLgqlbqW9zR'
    prefixer = Prefixer(qb64=aid)
    num = 14
    number = Number(num=num)
    snq = number.qb64
    snh = number.numh
    dig = 'ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux'
    diger = Diger(qb64=dig)

    # Test with single field namedtuple for data

    data = SealDigest(d=diger)
    clan = SealDigest
    cast = SealDigest(d=Castage(Diger))
    crew = SealDigest(d=dig)
    name = SealDigest.__name__

    dcast = cast._asdict()
    dcrew = crew._asdict()

    assert data._fields == SealDigest._fields
    klas = data.__class__
    assert klas == clan

    qb64 = diger.qb64
    qb2 = diger.qb2

    # Test data
    structor = Structor(data=data)
    assert structor.data == data
    assert structor.clan == clan
    assert structor.name == name
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.asdict == data._asdict()
    assert structor.asdict == {'d': diger}
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    # Test cast
    structor = Structor(cast=cast, crew=crew)
    #assert structor.data == data different instances so not ==
    assert structor.clan == clan
    assert structor.name == name
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    structor = Structor(cast=cast, qb64=qb64)
    assert structor.clan == clan
    assert structor.name == name
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    structor = Structor(cast=cast, qb64=qb64.encode())
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    structor = Structor(cast=cast, qb64=qb64.encode(), strip=True)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    ba = bytearray(qb64.encode())
    structor = Structor(cast=cast, qb64=ba, strip=True)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert not ba  # stripped so empty

    structor = Structor(cast=cast, qb2=qb2)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    structor = Structor(cast=cast, qb2=qb2, strip=True)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    ba = bytearray(qb2)
    structor = Structor(cast=cast, qb2=ba, strip=True)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert not ba  # stripped so empty

    # Test clan and cast
    structor = Structor(clan=clan, cast=cast, crew=crew)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    structor = Structor(clan=clan, cast=cast, qb64=qb64)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    structor = Structor(clan=clan, cast=cast, qb64=qb64.encode())
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    structor = Structor(clan=clan, cast=cast, qb2=qb2)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    # Test clan with cast and crew as dicts
    structor = Structor(clan=clan, cast=dcast, crew=dcrew)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    # Test no clan but with one or the other of cast and crew as dict or namedtuple
    structor = Structor(cast=cast, crew=dcrew)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    structor = Structor(cast=dcast, crew=crew)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    # creates custom clan since both cast and crew are dicts
    structor = Structor(cast=dcast, crew=dcrew)
    assert structor.data.__class__.__name__ == "d"
    assert structor.clan != clan
    assert structor.name == "d"
    assert structor.cast == cast  # tuple compare is by field value not type
    assert structor.cast.__class__.__name__ == "d"
    assert structor.crew == crew
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2


    # Test with multiple field namedtuple for data
    data = SealEvent(i=prefixer, s=number, d=diger)
    clan = SealEvent
    cast = SealEvent(i=Castage(Prefixer),
                     s=Castage(Number, 'numh'),
                     d=Castage(Diger))

    #naive cast doesn't know about prm for Number
    ncast = SealEvent(i=Castage(Prefixer),
                     s=Castage(Number),
                     d=Castage(Diger))
    crew = SealEvent(i=aid, s=snh, d=dig)

    # naive crew does't know about prm for Number
    ncrew = SealEvent(i=aid, s=snq, d=dig)
    name = SealEvent.__name__

    dcast = cast._asdict()
    dcrew = crew._asdict()

    assert data._fields == SealEvent._fields
    klas = data.__class__
    assert klas == clan

    qb64 = prefixer.qb64 + number.qb64 + diger.qb64  # ''.join(crew)
    qb2 = prefixer.qb2 + number.qb2 + diger.qb2

    # Test data
    structor = Structor(data=data)
    assert structor.data == data
    assert structor.clan == clan
    assert structor.cast == ncast
    assert structor.crew == ncrew
    assert structor.name == name
    assert structor.asdict == data._asdict()
    assert structor.asdict == \
    {
        'i': prefixer,
        's': number,
        'd': diger,
    }
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    # Test cast
    structor = Structor(cast=cast, crew=crew)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    structor = Structor(cast=cast, qb64=qb64)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    structor = Structor(cast=cast, qb64=qb64.encode())
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    structor = Structor(cast=cast, qb64=qb64.encode(), strip=True)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    ba = bytearray(qb64.encode())
    structor = Structor(cast=cast, qb64=ba, strip=True)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert not ba  # stripped so empty

    structor = Structor(cast=cast, qb2=qb2)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    structor = Structor(cast=cast, qb2=qb2, strip=True)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    ba = bytearray(qb2)
    structor = Structor(cast=cast, qb2=ba, strip=True)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2
    assert not ba  # stripped so empty

    # Test clan and cast
    structor = Structor(clan=clan, cast=cast, crew=crew)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    structor = Structor(clan=clan, cast=cast, qb64=qb64)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    structor = Structor(clan=clan, cast=cast, qb64=qb64.encode())
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    structor = Structor(clan=clan, cast=cast, qb2=qb2)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2


    # Test clan with cast and crew as dicts
    structor = Structor(clan=clan, cast=dcast, crew=dcrew)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2


    # Test no clan but with one or the other of cast and crew as dict or namedtuple
    structor = Structor(cast=cast, crew=dcrew)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    structor = Structor(cast=dcast, crew=crew)
    assert structor.clan == clan
    assert structor.cast == cast
    assert structor.crew == crew
    assert structor.name == name
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    # creates custom clan since both cast and crew are dicts
    structor = Structor(cast=dcast, crew=dcrew)
    assert structor.data.__class__.__name__ == "i_s_d"
    assert structor.clan != clan
    assert structor.name == "i_s_d"
    assert structor.cast == cast  # tuple compare is by field value not type
    assert structor.cast.__class__.__name__ == "i_s_d"
    assert structor.crew == crew
    assert structor.qb64 == qb64
    assert structor.qb64b == qb64.encode()
    assert structor.qb2 == qb2

    # Test no clan and cast or crew as dict
    with pytest.raises(kering.EmptyMaterialError):
        structor = Structor(cast=dcast)  # missing crew

    with pytest.raises(kering.InvalidValueError):
        structor = Structor(crew=crew)  # missing cast

    """End Test"""



def test_sealer_class():
    """
    test sealer class variables etc
    """
    assert Sealer.Clans == SClanDom
    assert Sealer.Casts == SCastDom
    assert Sealer.Names == \
    {
        ('d',): 'SealDigest',
        ('rd',): 'SealRoot',
        ('i', 's', 'd'): 'SealEvent',
        ('s', 'd'): 'SealTrans',
        ('i',): 'SealLast',
        ('bi', 'd'): 'SealBack',
        ('t', 'd'): 'SealKind',
    }

    """End Test"""


def test_sealer():
    """
    test sealer instance
    """

    with pytest.raises(kering.InvalidValueError):
        sealer = Sealer()  # test default


    aid = 'BN5Lu0RqptmJC-iXEldMMrlEew7Q01te2fLgqlbqW9zR'
    prefixer = Prefixer(qb64=aid)
    num = 14
    number = Number(num=num)
    snq = number.qb64
    snh = number.snh
    dig = 'ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux'
    diger = Diger(qb64=dig)

    # Test with single field namedtuple for data

    data = SealDigest(d=diger)
    clan = SealDigest
    cast = SealDigest(d=Castage(Diger))
    crew = SealDigest(d=dig)
    name = SealDigest.__name__

    dcast = cast._asdict()
    dcrew = crew._asdict()

    assert data._fields == SealDigest._fields
    klas = data.__class__
    assert klas == clan

    qb64 = diger.qb64
    qb2 = diger.qb2

    # Test data
    sealer = Sealer(data=data)
    assert sealer.data == data
    assert sealer.clan == clan
    assert sealer.name == name
    assert sealer.cast == cast
    assert sealer.crew == crew
    assert sealer.asdict == data._asdict()
    assert sealer.asdict == {'d': diger}
    assert sealer.qb64 == qb64
    assert sealer.qb64b == qb64.encode()
    assert sealer.qb2 == qb2

    # test round trip
    #sealer = Sealer(cast=S)

    # Test no clan but with one or the other of cast and crew as dict or namedtuple
    sealer = Sealer(crew=crew)  # uses known cast
    assert sealer.clan == clan
    assert sealer.name == name
    assert sealer.cast == cast
    assert sealer.crew == crew
    assert sealer.qb64 == qb64
    assert sealer.qb64b == qb64.encode()
    assert sealer.qb2 == qb2

    sealer = Sealer(crew=dcrew)  # uses known cast
    assert sealer.clan == clan
    assert sealer.name == name
    assert sealer.cast == cast
    assert sealer.crew == crew
    assert sealer.qb64 == qb64
    assert sealer.qb64b == qb64.encode()
    assert sealer.qb2 == qb2

    # uses known class
    sealer = Sealer(cast=dcast, crew=dcrew)
    assert sealer.clan == clan
    assert sealer.name == name
    assert sealer.cast == cast  # tuple compare is by field value not type
    assert sealer.crew == crew
    assert sealer.qb64 == qb64
    assert sealer.qb64b == qb64.encode()
    assert sealer.qb2 == qb2

    # Test with multiple field namedtuple for data

    data = SealEvent(i=prefixer, s=number, d=diger)
    clan = SealEvent
    cast = SealEvent(i=Castage(Prefixer),
                     s=Castage(Number, "numh"),
                     d=Castage(Diger))
    # naive cast since data does not provide prm for number
    ncast = SealEvent(i=Castage(Prefixer),
                     s=Castage(Number),
                     d=Castage(Diger))

    crew = SealEvent(i=aid, s=snh, d=dig)
    # naive crew since data does not provide prm for number
    ncrew = SealEvent(i=aid, s=snq, d=dig)

    name = SealEvent.__name__

    dcast = cast._asdict()
    dcrew = crew._asdict()

    assert data._fields == SealEvent._fields
    klas = data.__class__
    assert klas == clan

    qb64 = prefixer.qb64 + number.qb64 + diger.qb64  # ''.join(crew)
    qb2 = prefixer.qb2 + number.qb2 + diger.qb2

    # Test data
    sealer = Sealer(data=data)
    assert sealer.data == data
    assert sealer.clan == clan
    assert sealer.name == name
    assert sealer.cast == ncast
    assert sealer.crew == ncrew
    assert sealer.asdict == data._asdict()
    assert sealer.asdict == {'i': prefixer,
                             's': number,
                             'd': diger}
    assert sealer.qb64 == qb64
    assert sealer.qb64b == qb64.encode()
    assert sealer.qb2 == qb2

    # Test no clan but with one or the other of cast and crew as dict or namedtuple
    sealer = Sealer(crew=crew)  # uses known cast
    assert sealer.clan == clan
    assert sealer.name == name
    assert sealer.cast == cast
    assert sealer.crew == crew
    assert sealer.qb64 == qb64
    assert sealer.qb64b == qb64.encode()
    assert sealer.qb2 == qb2

    sealer = Sealer(crew=dcrew)  # uses known cast
    assert sealer.clan == clan
    assert sealer.name == name
    assert sealer.cast == cast
    assert sealer.crew == crew
    assert sealer.qb64 == qb64
    assert sealer.qb64b == qb64.encode()
    assert sealer.qb2 == qb2

    # uses known class
    sealer = Sealer(cast=dcast, crew=dcrew)
    assert sealer.clan == clan
    assert sealer.name == name
    assert sealer.cast == cast  # tuple compare is by field value not type
    assert sealer.crew == crew
    assert sealer.qb64 == qb64
    assert sealer.qb64b == qb64.encode()
    assert sealer.qb2 == qb2

    """Done Test"""



if __name__ == "__main__":
    test_structor_doms()
    test_structor_class()
    test_structor()
    test_sealer_class()
    test_sealer()



