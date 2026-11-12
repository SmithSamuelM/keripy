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
#     limb is Diger instance encoding of 256 bit branch path to node with MSbits
#         == depth == limb span
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
#     limb is Diger instance encoding of 256 bit branch path to leaf with MSbits
#         == 256 == MaxDepth == limb span
#         limb calculated on leaf info said using tree specific digest code so
#         limb inhabits same hash space as all other parts of tree.
#         Leaf info said may use different digest algo from tree wide digest algo.
#         Because limb makes secure committment to leaf info there is no security
#         need to store leaf info said per leaf. It may be stored in separate
#        field map indexed by limb for convenience.
LeafSaidage = namedtuple("LeafSaidage", "version tuid said depth limb")

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
#         limg is compute on leaf infos said bound to actual leaf info.
#         The info said may differ from the tree wide code for nodes and leafs
Leafage = namedtuple("Leafage", "depth limb")

# Partage as namedtuple of form (said, part)
#     said is qb2 of said of full Saidage for part
#     part is per part  namedtuple instance with qb2 values (Nodage or Leafage)
Partage = namedtuple("Partage", "said part")



class Siter:
    """Siter manages a SAIDed Info Tree (SIT)


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
        nodes (dict): Nodage instances indexed node said
        leaves (dict): Leafage instances with qb2 vals indexed by leaf said qb2
        infos (dict): leaf info saids as qb64 indexed by leaf limb qb64

    ToDo: change .nodes, .leaves, and .infos to have virtual interface
          that supports either in-memory and disk based storage
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
        self.infos = dict()


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

        # assign root nodage with qb2
        self.rootage = Nodage(depth=saidage.depth.qb2,
                              limb=saidage.limb.qb2,
                              left=saidage.left.qb2,
                              right=saidage.right.qb2)

        # populate tree
        self.nodes[saidage.said.qb2] = self.rootage
        root = Nodage(depth=saidage.depth,
                      limb=saidage.limb,
                      left=saidage.left,
                      right=saidage.right)

        # assign root node as Partage but with matter primitives values for compute
        self.root = Partage(said=saidage.said, part=root)



    def insert(self, leafer):
        """Insert leafer idempotently into tree

        Returns::
            result (Partage): instance (leaf said, leafage) when insert succeeded
                              None if leaf for leafer already in tree
                              raises error otherwise

        Parameters::
            leafer (Diger): instance encoding of leaf info said which said is
                            digest of actual leaf including

        """
        lepther = Number(num=256)  # leaf
        limber = Diger(ser=leafer.qb64b, code=self.Code)

        # create LeafSaidage and saidify
        saidage = LeafSaidage(version=self.leafVerser,
                                 tuid=self.tuider,
                                 said=Emptier, # placeholder
                                 depth=lepther,
                                 limb=limber)

        # replace saidage with SAIDed copy
        saidage = self.saidify(saidage=saidage)


        if saidage.said.qb2 in self.leaves:
            return None  # already inserted

        lsaider = saidage.said  # leaf said as Matter instance

        # create leafage with qb2 values
        leafage = Leafage(depth=saidage.depth.qb2,
                          limb=saidage.limb.qb2)

        # create lpart as Partage with (said, leafage) as qb2 values
        lpart = Partage(said=saidage.said.qb2, part=leafage)

        # create leaf as Leafage with matter primitives to enable compute
        leaf = Leafage(depth=saidage.depth, limb=saidage.limb)

        # attempt to insert
        inserted = False
        done = False

        nsaid, node = self.root  # start at root values are matter primitives

        while not done:
            depth = node.depth.num  # get int

            # walk down nodes if possible
            if node.left.nonce: # left child not empty
                if node.left.qb2 in self.nodes: # its a node
                    pass
                elif node.left.qb2 in self.leaves: # its a leaf
                    pass
                else:  # broken should not ever be
                    raise ValueError(f"Bad left child of node said={nsaid.qb64}")

            else:  # left child empty
                pass

            if node.right.nonce:  # right child not empty
                if node.right.qb2 in self.nodes: # its a node
                    pass
                elif node.right.qb2 in self.leaves: # its a leaf
                    pass
                else:  # broken should not ever be
                    raise ValueError(f"Bad right child of node said={nsaid.qb64}")

            else:  # right child empty
                pass


            done = True


        # do we want this to be Matter instances not qb2
        return (lpart if inserted else None)
