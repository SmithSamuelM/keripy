# -*- encoding: utf-8 -*-
"""
keri.smt.psmting module

Package level shared constants, functions, classes, errors etc

"""
from collections import namedtuple

from .. import Versionage, InvalidCodeError
from ..core import (MtrDex, DigDex, NonceDex, Noncer,  Ilker, Diger, Number)
from ..help import intToB64

Version = Versionage(major=0, minor=0)
MaxDepth = 256 # 256 bits or forks == limb span
MaxDepthBytes = 32  # MaxDepth in bytes equivalent

Emptier = Noncer(nonce="")  # empty string
EmptyQb2 = Emptier.qb2
EmptyQb64 = Emptier.qb64


# kith is the data type string of part, i.e. ilk for node and leaf parts
Kithage = namedtuple("Kithage", "node leaf")
Kiths = Kithage(node='nod', leaf="lea")

"""NodeSaidage Doc String
Full Set of Fields (per tree and per part) used to compute node SAID.
Values are Matter instances. The said field is computed using the .qb64 property
of each instance

Per tree/part type field values:
    kith is Ilker instance encoding of node kith, value == Kiths.node
    tuid is Noncer instance encoding the tree unique identifier.
        This default is a CESR encoded crypto strength 16 byte (128 bit) value.
        Because it is CESR encoded other namespacing information can be included
        in a bigger tuid value as long as it includes at least 128 bits of entropy
Per node fields:
    said is Noncer instance digesting NodeSaidage content using SAID protocol
        said filled with dummy values for digest then replaced with computed SAID
        saided data = kith+tuid+saiddummy+depth+limb+left+right
    depth is Number instance encoding 2 byte int of depth of node
    limb is Diger instance encoding of 256 bit branch path to node with MSbits
        == depth == limb span
    left is Noncer instance encoding said of left child (node, leaf or empty)
    right is Noncer instance encoding said of right child (node, leaf or empty)
"""
NodeSaidage = namedtuple("NodeSaidage", "kith tuid said depth limb left right")

"""LeafSaidage Doc String
Full Set of Fields (per tree and per part) used to compute leaf SAID.
Values are Matter instances. The said field is computed using the .qb64 property
of each instance

Per tree/part type field values:
    kith is Ilker instance encoding of leaf kith, value == Kiths.leaf
    tuid is Noncer instance encoding the tree unique identifier.
        This default is a CESR encoded crypto strength 16 byte (128 bit) value.
        Because it is CESR encoded other namespacing information can be included
        in a bigger tuid value as long as it includes at least 128 bits of entropy
Per leaf fields:
    said is Noncer instance digesting LeafSaidage content using SAID protocol
        said filled with dummy values for digest then replaced with computed SAID
        saided data = kith+tuid+saiddummy+depth+limb
    depth is Number instance encoding 2 byte int of potential depth of leaf
        leaf depth is always MaxDepth 256
    limb is Diger instance encoding of 256 bit branch path to leaf with MSbits
        == 256 == MaxDepth == limb span
        limb calculated on leaf info said using tree specific digest code so
        limb inhabits same hash space as all other parts of tree.
        Leaf info said may use different digest algo from tree wide digest algo.
        Because limb makes secure committment to leaf info there is no security
        need to store leaf info said per leaf. It may be stored in separate
        field map indexed by limb for convenience.
       """
LeafSaidage = namedtuple("LeafSaidage", "kith tuid said depth limb")

"""Nodage Doc String
A Nodage instance holds the per node fields where values use the appropriate
encoding depending on context.
For computation each field value is a Matter instance that enables convenient
access to the corresponding raw value of each instance.
For compact in memory storage each field value is serialized as the corresponding
.qb2 value of each instance.
For archival (disk) storage the field values are serialized as the corresponding
.qb64 value of each instance

Nodage fields:
    depth is Number instance NumDex.Short encoding 2 byte int node depth
    limb is Diger instance encoding the 256 bits of which the MS (big endian)
        depth bits provide the child forks to node. Depth == limb span MSbits
    left is Noncer instance of left child's Saidage:
        node or leaf or empty (only root node children can be empty)
    right is Noncer instance of right child's Saidage:
        node or leaf or empty (only root node children can be empty)
"""
Nodage = namedtuple("Nodage", "depth limb left right", defaults=(EmptyQb2, EmptyQb2))

"""Leafage Doc String
A Leafage instance holds the per leaf fields where values use the appropriate
encoding depending on context.
For computation each field value is a Matter instance that enables convenient
access to the corresponding raw value of each instance.
For compact in memory storage each field value is serialized as the corresponding
.qb2 value of each instance.
For archival (disk) storage the field values are serialized as the corresponding
.qb64 value of each instance

Leafage Fields:
    depth is Number instance NumDex.Short encoding 2 byte int leaf depth.
        The leaf depth is always MaxDepth == 256
    limb is Diger instance encoding the 256 bits (big endian) of potential
        child forks to leaf. All 256 bits are meaningful but for any leaf attached
        to a given node only the MS node depth+1 are used to address that leaf
        The limb digest is computed on leaf infos said which said is bound to
        actual leaf info. The info said algo may differ from the tree wide algo
        used to compute node and leaf saids.
"""
Leafage = namedtuple("Leafage", "depth limb")

"""Partage Doc String
Partage is namedtuple of tree part (node or leaf) of form (said, part).
A Partage instance field values use the appropriate encoding depending on context.
For computation each field value is a Matter instance that enables convenient
access to the corresponding raw value of each instance.
For compact in memory storage each field value is serialized as the corresponding
.qb2 value of each instance.
For archival (disk) storage the field values are serialized as the corresponding
.qb64 value of each instance

Partage fields:
    said is Diger instance of said of full Saidage for part
    part is either a Nodage or Leafage instance as appropriate for part
"""
Partage = namedtuple("Partage", "said part")



class Siter:
    """Siter manages a SAIDed Info Tree (SIT)


    Attributes::
        tuider (Noncer): instance encoding crypto 16 byte4 tree unique identifier
                       this ensures separation of digests within each unique tree.
        code (str): qb64 digest code shared by all node/leaf SAIDs
        root (Partage: instance of root Partage as (root said, rootage)) where
                       values are matter instances:
                       said is Diger instance, part is Nodage instance whose
                           values are Matter instances
        nodes (dict): Nodage instances indexed by node said
        leaves (dict): Leafage instances indexed by leaf said
        infos (dict): leaf info saids as indexed by leaf limb

    ToDo: change .nodes, .leaves, and .infos to have virtual interface
          that supports either in-memory and disk based storage
    """
    Dummy = '#'  # default dummy for computing SAIDs
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
            # create  dumied said field as bytes
            dqb64b[label] = (cls.Dummy * Noncer._fullSize(code)).encode()
        except KeyError as ex:
            raise ValueError(f"Invalid said field {label=}") from ex

        ser = b''.join(dqb64b.values())  # dummied ser
        saider = Noncer(ser=ser, code=code)
        if saider.code not  in DigDex:  # reforce strict so must be valid digest
            raise InvalidCodeError(f"Unsupported Digest code={saider.code}.")

        rkwa = dict()  # dict for namedtuple replace of said field with saider
        rkwa[label] = saider
        return saidage._replace(**rkwa)


    @staticmethod
    def extendLimbRaw(limb, span=0, right=False):
        """Extends limb of span (depth) with bit value given by right and
        returns new limb extended by 1 bit.

        Returns:
            result (tuple): (limb, span) where:
                            limb is extended limb with span+1 MSbits. All other bits
                                masked to 0s.
                            span is span+1

        Parameters:
            limb (int): 256 bit limb path with span MSbits to be extended
            span (int): span (depth) of limb 0-255 MSbits
            right (bool): True means extend with 1 (right child bit)
                          False means extend with 0 (left child bit)

        Usage::
            given limber as Diger instance of limb
            given spanner as Number instance of depth

            limb = Sider.extendLimbRaw(limb=int.from_bytes(limber.raw),
                                    span=spanner.num)

            or

            limb = Sider.extendLimbRaw(limb=int.from_bytes(limber.raw),
                                    span=spanner.num,
                                    right=True)

            limber = Diger(raw=limb.to_bytes(MaxDepthBytes))
            depther = Number(num=depther.num+1)
        """
        if span >= MaxDepth:
            raise ValueError(f"Invalid {span=} greater than MaxDepth")

        mask = ((1 << span) - 1)  # mask of 1s of length span
        limb = (limb >> (MaxDepth - span)) & mask
        limb = limb << 1  # extend with zero
        if right:
            limb |= 1  # make lsb 1
        span += 1
        return (limb << (MaxDepth - span), span)


    @staticmethod
    def extendLimb(limber, spanner, right=False):
        """Extends limber of span spanner with bit value given by left and
        returns tuple of (limber, spanner) where:
            limber extended by 1 bit and
            spanner incremented by 1.

        Returns:
            result (tuple): of form (limer, spanner) where:
                            limber is Diger instance of extended limb
                            spanner is Number instance of incremented span

        Parameters:
            limber (Diger): instance encoding 256 bit limb path with span MSbits
                            to be extended
            spanner (Number): instance encoding limb span MSbits [0..255]
            right (bool): True means extend with 1 (right child bit)
                          False means extend with 0 (left child bit)

        Usage::
            given limber as Diger instance of limb
            given spanner as Number instance of depth

            limber, spanner = Sider.extendLimb(limber=limber,
                                                    spanner=spanner)

            or

            limber, spanner = Sider.extendLimb(limb=int.from_bytes(limber.raw),
                                    span=depther.num)
        """
        code = limber.code  # save to recreate
        limb = int.from_bytes(limber.raw)
        span = spanner.num
        limb, span = Siter.extendLimbRaw(limb=limb, span=span, right=right)
        limber = Diger(raw=limb.to_bytes(MaxDepthBytes), code=code)
        spanner = Number(num=span)
        return (limber, spanner)



    def __init__(self, tuid=None, code=MtrDex.Blake3_256, **kwa):
        """Initialize instance

        Parameters::
            tuid (str|bytes|None): qb64 or qb64b of 16 byte tree unique identifier.
                                   None means generate crypto strength value.
                                   Use Noncer to create from raw 16 bytes.
            code (str|bytes): tree wide digest code (qb64 or qb64b) for saids


        """
        self.tuider = Noncer(nonce=tuid)  # None generates crypto random value
        self.code = code if code is not None else self.Code
        self.nodes = dict()
        self.leaves = dict()
        self.infos = dict()


        # make and insert root node in .nodes
        # depth is 0, limb is all zeros, left is empty, right is empty
        rootage = Nodage(depth=Number(num=0),
                         limb=Diger(raw=bytes(MaxDepthBytes), code=self.code),
                         left=Noncer(nonce=""),
                         right=Noncer(nonce=""))
        self.root = Partage(self.saidNode(rootage), rootage)
        self.pinNode(saider=self.root.said, nodage=self.root.part)


    def saidNode(self, nodage):
        """Computes and returns said of node as Matter primitive where said is
        computed with a NodeSaidage derived from nodage supplemented with per
        tree and per part field values taken from self (Siter instance)
        The said is essentially 'hashing' or digesting the node.

        Returns::
            saider (Diger): instance where said is computed from NodeSaidage
                            derived from nodage as supplemented with tree fields

        Parameters::
            nodage (Nodage): instance of nodage whose field values are Matter
                             instances
        """
        saidage = NodeSaidage(kith=Ilker(ilk=Kiths.node, strict=False),
                              tuid=self.tuider,
                              said=Noncer(nonce=""),
                              depth=nodage.depth,
                              limb=nodage.limb,
                              left=nodage.left,
                              right=nodage.right)
        saidage = self.saidify(saidage)
        return saidage.said


    def saidLeaf(self, leafage):
        """Computes and returns said of leaf as Matter primitive where said is
        computed with a LeafSaidage derived from leafage supplemented with per
        tree and per part field values taken from self (Siter instance)
        The said is essentially 'hashing' or digesting the leaf.

        Returns::
            saider (Diger): instance where said is computed from LeafSaidage
                            derived from leafage as supplemented with tree fields

        Parameters::
            leafage (Leafage): instance of leafage whose field values are Matter
                             instances
        """
        saidage = LeafSaidage(kith=Ilker(ilk=Kiths.leaf, strict=False),
                              tuid=self.tuider,
                              said=Noncer(nonce=""),
                              depth=leafage.depth,
                              limb=leafage.limb)
        saidage = self.saidify(saidage)
        return saidage.said


    def putNode(self, saider, nodage):
        """Puts node given by nodage into .nodes at said given by .saider
        Put is idempotent. If node already exists put does not overwrite it.

        Abstract interface to .nodes storage of Nodage for each node indexed
        by is said. Interface uses Matter instances for said and Nodage field
        values that hide the underlying serialization used by the storage.

        For in memory use compact ,.qb2 values.
        For archival on disk use .qb64 values.

        Returns::
            result (bool): True if nodage added to .nodes
                           False if entry at saider said already exists do
                               does not overwrite

        Parameters::
            saider (Diger): instance encoding said of nodage
            nodage (Nodage): instance whose field values are Matter instances

        """
        if saider.qb2 in self.nodes:
            return False  # already in .nodes

        # convert to qb2 for compact storage
        nodage = Nodage(depth=nodage.depth.qb2,
                        limb = nodage.limb.qb2,
                        left=nodage.left.qb2,
                        right=nodage.right.qb2)
        self.nodes[saider.qb2] = nodage
        return True


    def pinNode(self, saider, nodage):
        """Pins node given by nodage into .nodes at said given by .saider
        Pin is not idempotent. If node already exists pin overwrites it.

        Abstract interface to .nodes storage of Nodage for each node indexed
        by is said. Interface uses Matter instances for said and Nodage field
        values that hide the underlying serialization used by the storage.

        For in memory use compact ,.qb2 values.
        For archival on disk use .qb64 values.

        Parameters::
            saider (Diger): instance encoding said of nodage
            nodage (Nodage): instance whose field values are Matter instances

        """
        # convert to qb2 for compact storage
        nodage = Nodage(depth=nodage.depth.qb2,
                        limb = nodage.limb.qb2,
                        left=nodage.left.qb2,
                        right=nodage.right.qb2)
        self.nodes[saider.qb2] = nodage


    def getNode(self, saider):
        """Gets node from .nodes at said given by saider.

        Abstract interface to .nodes storage of Nodage for each node indexed
        by is said. Interface uses Matter instances for said and Nodage field
        values that hide the underlying serialization used by the storage.

        For in memory use compact ,.qb2 values.
        For archival on disk use .qb64 values.

        Returns::
            nodage (Nodage|None): instance whose values are Matter instances.
                                  None when not found

        Parameters::
            saider (Diger): instance encoding said of nodage

        """
        if nodage := self.nodes.get(saider.qb2):
            # convert to Matter instances for computation
            nodage = Nodage(depth=Number(qb2=nodage.depth),
                            limb=Diger(qb2=nodage.limb),
                            left=Noncer(qb2=nodage.left),
                            right=Noncer(qb2=nodage.right))
        return nodage


    def remNode(self, saider):
        """Removes node from .nodes at said given by saider.

        Abstract interface to .nodes storage of Nodage for each node indexed
        by is said. Interface uses Matter instances for said and Nodage field
        values that hide the underlying serialization used by the storage.

        For in memory use compact ,.qb2 values.
        For archival on disk use .qb64 values.

        Returns::
            result (bool): True if entry at saider in .nodes found and removed
                           False if no entry at saider in .nodes

        Parameters::
            saider (Diger): instance encoding said of nodage

        """
        try:
            del self.nodes[saider.qb2]
        except KeyError as ex:
            return False

        return True


    def putLeaf(self, saider, leafage):
        """Puts leaf given by leafage into .leaves at said given by .saider
        Put is idempotent. If leaf already exists put does not overwrite it.

        Abstract interface to .leaves storage of Leafage for each leaf indexed
        by is said. Interface uses Matter instances for said and Leafage field
        values that hide the underlying serialization used by the storage.

        For in memory use compact ,.qb2 values.
        For archival on disk use .qb64 values.

        Returns::
            result (bool): True if leafage added to .leaves
                           False if entry at saider said already exists do
                               does not overwrite

        Parameters::
            saider (Diger): instance encoding said of nodage
            leafage (Leafage): instance whose field values are Matter instances

        """
        if saider.qb2 in self.leaves:
            return False  # already in .leaves

        # convert to qb2 for compact storage
        leafage = Leafage(depth=leafage.depth.qb2,
                        limb = leafage.limb.qb2)
        self.leaves[saider.qb2] = leafage
        return True


    def pinLeaf(self, saider, leafage):
        """Pins leaf given by leafage into .leaves at said given by .saider
        Pin is not idempotent. If leaf already exists pin overwrites it.

        Abstract interface to .leaves storage of Leafage for each leaf indexed
        by is said. Interface uses Matter instances for said and Leafage field
        values that hide the underlying serialization used by the storage.

        For in memory use compact ,.qb2 values.
        For archival on disk use .qb64 values.

        Parameters::
            saider (Diger): instance encoding said of nodage
            leafage (Leafage): instance whose field values are Matter instances

        """
        # convert to qb2 for compact storage
        leafage = Leafage(depth=leafage.depth.qb2,
                          limb = leafage.limb.qb2)
        self.leaves[saider.qb2] = leafage


    def getLeaf(self, saider):
        """Gets leaf from .leaves at said given by saider.

        Abstract interface to .leaves storage of Leafage for each leaf indexed
        by is said. Interface uses Matter instances for said and Leafage field
        values that hide the underlying serialization used by the storage.

        For in memory use compact ,.qb2 values.
        For archival on disk use .qb64 values.

        Returns::
            leafage (Leafage|None): instance whose values are Matter instances.
                                    None when not found

        Parameters::
            saider (Diger): instance encoding said of leafage

        """
        if leafage := self.leaves.get(saider.qb2):
            # convert to Matter instances for computation
            leafage = Leafage(depth=Number(qb2=leafage.depth),
                              limb=Diger(qb2=leafage.limb))
        return leafage


    def remLeaf(self, saider):
        """Removes leaf from .leaves at said given by saider.

        Abstract interface to .leaves storage of Leafage for each leaf indexed
        by is said. Interface uses Matter instances for said and Leafage field
        values that hide the underlying serialization used by the storage.

        For in memory use compact ,.qb2 values.
        For archival on disk use .qb64 values.

        Returns::
            result (bool): True if entry at saider in .leaves found and removed
                           False if no entry at saider in .leaves

        Parameters::
            saider (Diger): instance encoding said of leafage

        """
        try:
            del self.leaves[saider.qb2]
        except KeyError as ex:
            return False

        return True


    def insert(self, leafer):
        """Insert leafer idempotently into tree

        Returns::
            result (Partage): instance (leaf said, leafage) when insert succeeded
                              None if leaf for leafer already in tree
                              raises error otherwise

        Parameters::
            leafer (Diger): instance encoding of leaf info said which said is
                            digest of actual leaf including


        Logic:
            leaf can only attach to child of node on side given by bit in leaf
            limb which bit is located above the node depth. This leaves room
            for one more nodes to interpose allowing leaf to rebalance to move
            to correct child of interposed node. If leaf limb side bit does not
            exactly match side at depth+1 of node  to which it is attached then
            there is no way to move it later to rebalance. Consequently leaves
            attached to root must always attach to side given by bit at depth=1
            in leaf limb (zero based bit index 0 from left, bit index 255 from right,
            This means that one side of the root may remain empty always until
            a leaf is inserted whose depth 1 bit matches the empty side.
            This means that logic for attaching leaf to empty root is simple.
            Just attach to side given by depth 1 limb bit. Root at depth 0.

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


        # create leafage with qb2 values as variant to attach, insert, and return
        leafage = Leafage(depth=saidage.depth.qb2,
                          limb=saidage.limb.qb2)

        #leaf partage to return when successful insert
        partage = Partage(said=saidage.said.qb2, part=leafage)

        # create leaf as Leafage with matter primitives to enable compute
        lsaider = saidage.said  # leaf said as Matter instance
        leaf = Leafage(depth=saidage.depth, limb=saidage.limb)
        leaflimb = int.from_bytes(leaf.limb.raw)  # convert leaf limb to int

        # Setup for insert
        inserted = False
        done = False
        nsaid, node = self.root  # start at root with values as matter primitives
        while not done:
            depth = node.depth.num  # get current node depth as int
            limb = int.from_bytes(node.limb.raw)  # convert curent node limb to int

            # walk down nodes if possible
            # leftage is retrieved child qb2, nodage or leafage, empty is None
            # rightage is retrieved child qb2, nodage or leafage, empty is None
            if node.left.nonce: # left child not empty
                if (leftage := self.nodes.get(node.left.qb2)): # its a node
                    leftIsNode = True
                    # match limbs and walk down left side if match
                    # right shift to prune suffix and mask with 1s of size depth
                    mask = ((1 << depth) - 1)
                    leafprefix = (leaflimb >> (MaxDepth - depth)) & mask
                    nodeprefix = (limb >> (MaxDepth - depth)) & mask
                    if leafprefix == nodeprefix:  # match so walk down
                        # replace node with left child node to walk down one
                        nsaid = Noncer(qb2=node.left.qb2)
                        node = Nodage(depth=Number(qb2=leftage.depth),
                                      limb=Diger(qb2=leftage.limb),
                                      left=Noncer(qb2=leftage.left),
                                      right=Noncer(qb2=leftage.right))
                        continue  # resume on next level down on left
                elif leftage := self.leaves.get(node.left.qb2): # its a leaf
                    leftIsNode = False
                else:  # broken should not ever be
                    raise ValueError(f"Bad left child of node said={nsaid.qb64}")
            else:  # left child empty
                leftage = None

            if node.right.nonce: # right child not empty
                if (rightage := self.nodes.get(node.right.qb2)): # its a node
                    rightIsNode = True
                    # match limbs and walk down right side if match
                    # right shift to prune suffix and mask with 1s of size depth
                    mask = ((1 << depth) - 1)
                    leafprefix = (leaflimb >> (MaxDepth - depth)) & mask
                    nodeprefix = (limb >> (MaxDepth - depth)) & mask
                    if leafprefix == nodeprefix:  # match so walk down
                        # replace node with left child node to walk down one
                        nsaid = Noncer(qb2=node.right.qb2)
                        node = Nodage(depth=Number(qb2=rightage.depth),
                                      limb=Diger(qb2=rightage.limb),
                                      left=Noncer(qb2=rightage.left),
                                      right=Noncer(qb2=rightge.right))
                        continue  # resume on next level down on right

                elif rightage := self.leaves.get(node.right.qb2): # its a leaf
                    rightIsNode = False
                else:  # broken should not ever be
                    raise ValueError(f"Bad right child of node said={nsaid.qb64}")
            else:  # right child empty
                rightage = None

            # When we get here, then we can't walk down a node on neither side.
            # an unwalkable node on a side means that the node limb path (size depth)
            # on that side is not a prefix of the leaf limb path so leaf must go
            # on other side. We must then do leaf rebalancing logic
            # Cases:
            #    a) left is an unwalkable node and right is leaf or empty
            #    b) right is an unwalkable node and left is leaf or empty
            #    c) left and right are both leaves or empty

            if leftage and leftIsNode:  # case a) left is an unwalkable node,
                if not rightage:  # rightage is empty so attach leaf to right child
                    # assumes by construction that leaf prefix is compatible
                    # with right child
                    # attach leaf to right child of current, replace empty
                    nodage = Nodage(depth=node.depth.qb2,
                                    limb=node.limb.qb2,
                                    left=node.left.qb2,
                                    right=leafage)
                    self.nodes[nsaid.qb2] = nodage  # replace prior tuple
                    self.leaves[partage.said] = partage.part  # insert leaf
                    self.infos[saidage.limb.qb64] = leafer.qb64  # insert info
                    inserted = True
                    done = True

                else: # right is leaf so add node on right holding old and new leaves.
                    # at first fork where old/new leaf limbs differ (fork height)
                    # Insert node with leaves on correct sides as determined
                    # by limb difference bit (left or right side)
                    oldage = self.leaves[node.right.qb2]  # get old leaf qb2
                    newsaid, nodage = self.fork(oldage=oldage,
                                              newage=leafage,
                                              depth=node.depth,
                                              limb=node.limb,
                                              side=True)
                    self.nodes[newsaid] = nodage  # replace prior tuple
                    self.leaves[partage.said] = partage.part  # insert leaf
                    self.infos[saidage.limb.qb64] = leafer.qb64  # insert info
                    inserted = True
                    done = True




            elif rightage and rightIsNode:  # case b) right is an unwalkable node,
                if not leftage:  # leftage is empty so attach leaf to left child
                    # assumes by construction that leaf prefix is compatible
                    # with left child
                    # attach leaf to left child of current, replace empty
                    nodage = Nodage(depth=node.depth.qb2,
                                    limb=node.limb.qb2,
                                    left=leafage,
                                    right=node.right.qb2)
                    self.nodes[nsaid.qb2] = nodage  # replace prior tuple
                    self.leaves[partage.said] = partage.part  # insert leaf
                    self.infos[saidage.limb.qb64] = leafer.qb64  # insert info
                    inserted = True
                    done = True

                else: # right is leaf so add node on right holding old and new leaves.
                    # at first fork where old/new leaf limbs differ (fork height)
                    # Insert node with leaves on correct sides as determined
                    # by limb difference bit (left or right side)
                    oldage = self.leaves[node.right.qb2]  # get old leaf qb2
                    newsaid, nodage = self.fork(oldage=oldage,
                                                newage=leafage,
                                                depth=node.depth,
                                                limb=node.limb,
                                                side=False)
                    self.nodes[newsaid] = nodage  # replace prior tuple
                    self.leaves[partage.said] = partage.part  # insert leaf
                    self.infos[saidage.limb.qb64] = leafer.qb64  # insert info
                    inserted = True
                    done = True

            else: # case c) left and right are both leaves or empty
                pass





            done = True


        # do we want this to be Matter instances not qb2
        return (partage if inserted else None)


    def fork(self, oldage, newage, depth, limb, side):
        """Given two leaves oldage and newage, create a node and attach the
        leaves to appropriate children given by the lowest depth where the
        limbs of the two leaves differ. Returns the newly created node

        Parameters:
            old (Leafage): instance (said, part) with said as qb2 where
                           part is Leafage instance with qb2 values
            new (Leafage): instance (said, part) with said as qb2 where
                           part is Leafage instance with qb2 values
            depth (Number):  depth of prior node
            limb (Diger): limb of prior node
            side (bool): side to attach new node to prior node.
                         False is left side, True is right side
                         Enables calculation of new limb from prior limb

        Returns:
            nodepartage (Partage): instance (said, part) where:
                            said is qb2 of node
                            part is Nodage instance with qb2 values
                            old and new provide left and right as appropriate

        """
        # make matter instance value variant of oldage leaf
        old = Leafage(depth=Number(qb2=oldage.depth, limb=Diger(qb2=oldage.limb)))
        oldlimb = int.from_bytes(old.limb.raw)

        # make matter instance value variant of newage leaf
        new = Leafage(depth=Number(qb2=newage.depth, limb=Diger(qb2=newage.limb)))
        newlimb = int.from_bytes(new.limb.raw)

        for i in range(MaxDepth - 1, 0, -1):  # start at MSbit of limbs
            oldbit = (oldlimb >> i) & 1  # mask off all but lsb after shift
            newbit = (newlimb >> i) & 1  # mask off all but lsb after shift
            if oldbit != newbit:
                if oldbit:
                    left = new
                    right = old

                else:
                    left = old
                    right = new
                break
