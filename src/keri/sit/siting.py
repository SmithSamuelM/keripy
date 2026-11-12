# -*- encoding: utf-8 -*-
"""
keri.smt.psmting module

Package level shared constants, functions, classes, errors etc

"""
from collections import namedtuple

from .. import Versionage, InvalidCodeError
from ..core import (MtrDex, DigDex, NonceDex, Noncer,  Verser, Tagger, Diger, Number)
from ..help import intToB64

Version = Versionage(major=0, minor=0)
MaxDepth = 256 # 256 bits or forks == limb span
MaxDepthBytes = 32  # MaxDepth in bytes equivalent

Emptier = Noncer(nonce="")  # empty string
EmptyQb2 = Emptier.qb2
EmptyQb64 = Emptier.qb64

Kithage = namedtuple("Kithage", "node leaf")
Kiths = Kithage(node='node', leaf="leaf")

# Full Set of Fields (per tree and per part) holder Matter instances for
# computing node SAID. The said field is computed using qb64 of fields
# Per tree fields:
#     version is Verser instance encoding of node kith and SIT algo version where:
#         proto is node kith
#         pvrsn is major minor version of SIT algorithm svrsn
#     tuid is Noncer instance encoding the tree unique identifier
# Per node fields:
#     said is Noncer instance encoding SAIDage including per tree and per node fields
#         said filled with dummy values for digest then replaced with computed SAID
#         saided data = version+tuid+saiddummy+depth+limb+left+right
#     depth is Number instance encoding 2 byte int of depth of node
#     limb is Diger instance encoding 256 bit branch path to node with MSbits
#         of limb span == depth
#     left is Noncer instance encoding said of left child (node, leaf or empty)
#     right is Noncer instance encoding said of right child (node, leaf or empty)
NodeSaidage = namedtuple("NodeSaidage", "version tuid said depth limb left right")

# Full Set of Fields (per tree and per part) holder Matter instances for
# computing leaf SAID. The said field is computed using qb64 of fields.
# Per tree fields:
#     version is Verser instance encoding of leaf kith and SIT algo version where:
#         proto is leaf kith
#         pvrsn is major minor version of SIT algorithm svrsn
#     tuid is Noncer instance encoding the tree unique identifier
# Per leaf fields:
#     said is Noncer instance encoding SAIDage including per tree and per leaf fields
#         said filled with dummy values for digest then replaced with computed SAID
#         saided data = version+tuid+saiddummy+depth+limb+info
#     depth is Number instance encoding 2 byte int of potential depth of leaf
#         leaf depth is always MaxDepth 256
#     limb is Diger instance encoding 256 bit branch path to leaf with MSbits
#         of limb span == 256 ==MaxDepth
#     info is Diger instance encoding said of leaf info using info specific digest code
LeafSaidage = namedtuple("LeafSaidage", "version tuid said depth limb info")

# Per node fields in compact qb2 as node tuple (said, node) where:
#     said is qb2 of said computed for NodeSaidage
#     node is nodage instance with each field value encoded as qb2
# Nodage fields:
#     depth is qb2 of Number Short encoded 2 byte int of depth of node
#     limb is qb2 Digest encoded 256 bit branch path to node with MSbits of limb span == depth
#     left is qb2 said Digest of left child's Saidage (node or leaf or empty if root node)
#     right is qb2 said Digest right child's Saidage (node or leaf or empty if root node)
Nodage = namedtuple("Nodage", "depth limb left right", defaults=(EmptyQb2, EmptyQb2))

# Per leaf fields in compact qb2 as leaf tuple (said, leaf) where:
#     said is qb2 of said computed for LeafSaidage
#     leaf is leafage instance with each field value encoded as qb2
# Leafage Fields:
#     depth is qb2 of Number Short encoded 2 byte int of potential depth of leaf, always 256
#     limb is qb2 of Digest encoded 256 bit branch path to leaf with MSbits == 256
#     info is qb2 of Digest encoded said of bound info to leaf.
#         The info said may differ from the tree wide code for nodes and leafs
Leafage = namedtuple("Leafage", "depth limb info")

# Partage as namedtuple of form (said, part)
#     said is qb2 of said of full Saidage for part
#     part is per part  namedtuple instance with qb2 values (Nodage or Leafage)
Partage = namedtuple("Partage", "said part")



class Siter:
    """Siter manages a SAIDed Info Tree (SIT)


    kith node or leaf
    version kith+major+minor  nodever = node+major+minor  leafver = leaf+major+minor
    node saidage:  nodever tuid said depth path left righ
    leaf saidage:  leafver tuid said depth limb info
    Nodage (depth, limb, left, right) in qb2
    node (said, nodage)
    Leafage (depth limb info) in qb2
    leaf (said, leafage)

    per node item (key, val) = (said, nodage)
    per leaf item (key, val) = (said, leafage)

    Attributes::
        svrsn (Versionage): Sit algorithm version for tree as major minor
                            Base64 encoded as Mmm where
                                M=major int [0..63] encoded as B64 char,
                                mm=minor int [0..4095] encoded two B64 chars
        tuider (Noncer): instance encoding crypto 16 byte4 tree unique identifier
                       this ensures separation of digests within each unique tree.
        nodeVerser (Verser): instance with proto = node kith 'node' and pvrsn=svrsn
        leafVerser (Verser): instance with proto = leaf kith 'leaf' and pvrsn=svrsn
        code (str): qb64 digest code shared by all node/leaf SAIDs
        rootage (Nodage): instance of root nodage
        root (Partage: instance of root Partage as (root said, rootage))
        nodes (dict): indexed by SAID of each node
                      to be modified with virtual interface
                      that supports either in-memory and disk based storage
        leaves (dict): indexed by SAID of each leaf


    """
    Dummy = b'#'  # default dummy for computing SAIDs always bytes
    Code = MtrDex.Blake3_256  # class default code for computing SAIDs

    @classmethod
    def saidify(cls, saidage, label='said', code=None):
        """Computes said of saidage and returns saidified copy of saidage where
        said field value given by label is replaced with computed said as saider.

        Returns::
            saidage (namedtuple): instance as saidified replacement of saidage

        Parameters::
            saidage (namedtuple): instance from which to compute and replace said
                                  field given by label
            label (str): field to hold said
            code (str|None): digest code for computing said. None means cls.Code


        Eventually when we have a Structor subclass with group code we can
        use a Structor instance to calculate the said
        """

        code = code if code is not None else cls.Code

        dqb64b = {l: v.qb64b for l, v in saidage._asdict().items()}  # get .qb64b of each field
        try:
            dqb64b[label] = cls.Dummy * Noncer._fullSize(code)  # dumify said field
        except KeyError as ex:
            raise ValueError(f"Invalid said field {label=}") from ex

        ser = b''.join(dqb64b.values())  # dummied ser
        saider = Noncer(ser=ser, code=code)
        if saider.code not  in DigDex:  # reforce strict so must be valid digest
            raise InvalidCodeError(f"Unsupported Digest code={saider.code}.")

        rkwa = dict()  # dict for namedtuple replace of said field with saider
        rkwa[label] = saider

        return saidage._replace(**rkwa)



    def __init__(self, svrsn=None, tuid=None, code=MtrDex.Blake3_256, **kwa):
        """Initialize instance

        Parameters::
            svrsn (Versionage|None): SIT algorithm version tuple (major, minor)
                                     None means use Version
            tuid (str|bytes|None): qb64 or qb64b of 16 byte tree unique identifier.
                                   None means generate crypto strength value.
                                   Use Noncer to create from raw 16 bytes.
            code (str|bytes): tree wide digest code (qb64 or qb64b) for saids


        """
        self.svrsn = svrsn if svrsn is not None else Version
        self.tuider = Noncer(nonce=tuid)  # None generates crypto random value
        self.code = code if code is not None else self.Code
        self.nodeVerser = Verser(proto=Kiths.node, pvrsn=self.svrsn)
        self.leafVerser = Verser(proto=Kiths.leaf, pvrsn=self.svrsn)
        self.nodes = dict()
        self.leaves = dict()


        # make root node and insert in .nodes
        # root depther
        repther = Number(num=0)  # root depth always 0
        # root limber, all zeros
        rimber = Diger(raw=bytes(MaxDepthBytes), code=self.code)
        # create saidage with matter primitive instances
        saidage = NodeSaidage(version=self.nodeVerser,
                             tuid=self.tuider,
                             said=Emptier, # placeholder
                             depth=repther,
                             limb=rimber,
                             left=Emptier,
                             right=Emptier)

        # replace rootsaidage with SAIDed copy
        saidage = self.saidify(saidage=saidage, label="said", code=self.code)

        # assign root nodage
        self.rootage = Nodage(depth=saidage.depth.qb2,
                              limb=saidage.limb.qb2,
                              left=saidage.left.qb2,
                              right=saidage.right.qb2)

        # assign root node
        self.root = Partage(said=saidage.said.qb2, part=self.rootage)

        # populate tree
        self.nodes[self.root.said] = self.root.part



