# -*- encoding: utf-8 -*-
"""
keri.smt.psmting module

Package level shared constants, functions, classes, errors etc

"""
from collections import namedtuple

from ..core import MtrDex, DigDex, NonceDex, Noncer, Tagger, Diger, Number
from ..help import intToB64

MaxLimbLenBytes = 32
MaxHeight = 2 ** 3 * MaxLimbLenBytes  # 256
MaxLimbLength = MaxHeight
emptier = Noncer(nonce="")  # empty string
EmptyQb2 = emptier.qb2
EmptyQb64 = emptier.qb64

# Full Set of Fields for computing node SAID includes per tree fields
# all fields as Matter primitive instances. SAID computed using qb64 encoding
# Per tree fields:
#   version is combined field with tree version and tree wide digest code
#   tuid is tree unique identifier
# Per node fields:
#   said is digest of full node including per tree and per node fields
#       said filled with dummy values for digest then replaced with computed SAID
#       saided data = version+tuid+saiddummy+height+limb+left+right
#   height is encoded 2 byte int of height of node
#   limb is encoded 256 bit branch path to node with depth=256-height MSbits
#   left is encoded said of left child (node or leaf or empty if root node)
#   right is encoded said of right child (node or leaf or empty if root node)
NodeSaidage = namedtuple("NodeSaidage", "version tuid said height limb left right",
                        defaults = ("EmptyQb2", "EmptyQb2"))

# Full Set of Fields for computing leaf SAID includes per tree fields
# all fields as Matter primitive instances. SAID computed using qb64 encoding
# Per tree fields:
#   version is combined field with tree version and tree wide digest code
#   tuid is tree unique identifier
# Per leaf fields:
#   said is digest of full leaf including per tree and per leaf fields
#       said filled with dummy values for digest then replaced with computed SAID
#       saided data = version+tuid+saiddummy+height+limb+info
#   height is encoded 2 byte int of height of leaf (always zero)
#   limb is encoded 256 bit branch path to leaf
#   info is encoded said of leaf info using info specific digest code
LeafSaidage = namedtuple("LeafSaidage", "version tuid said height limb info")

# Per node fields in compact qb2 as node tuple (said, leaf) where:
#     said is qb2 of said computed for NodeSaidage
#     node is nodage instance with each field in qb2
# Nodage fields:
#   height is qb2 Short of 2 byte int of height of node
#   limb is qb2 Digest encoded 256 bit branch path to node with depth=256-height MSbits
#   left is qb2 said Digest of left child's Saidage (node or leaf or empty if root node)
#   right is qb2 said Digest right child's Saidage (node or leaf or empty if root node)
Nodage = namedtuple("Nodage", "height limb left right", defaults=(EmptyQb2, EmptyQb2))

# Per leaf fields in compact qb2 as leaf tuple (said, leaf) where:
#     said is qb2 of said computed for LeafSaidage
#     leaf is leafage instance with each field in qb2
# Leafage Fields:
#   height is qb2 Short of 2 byte int of height of leaf (always 0)
#   limb is qb2 Digest encoded 256 bit branch path to leaf
#   info is qb2 said of bound info to leaf. The info said may use a different
#       code than the tree wide code
Leafage = namedtuple("Leafage", "height limb info")



class Siter:
    """Siter manages a SAIDed Info Tree (SIT)


    kith node or leaf
    version kith+major+minor  nodever = node+major+minor  leafver = leaf+major+minor
    node:  nodever said tuid height path left righ
    leaf:  keafver said tuid height limb info
    NodeSaidage
    LeafSaidage
    Nodage (height limb left right)
    per node item (key, val) = (said, nodage)
    Leafage (height limb info)
    per leaf item (key, val) = (said, leafage)

    Attributes::
        tuid (str): qb64 of tree unique idendifier (TUID) that is CESR encoded
                    16 byte unique value for tree. This ensures separation of
                    digests within each unique tree. Use Noncer to encode/decode
        verdig (str): qb64 encoded 8 char code + 3 char tree version + 4 char
                       tree wide digest code
                        First char is major version as one Base64 char (0-63)
                        Next two characters are minor version as two Base64 chars (0-4095)
                        Last 4 chars are '_' prefixed digest code.
                            'E' encodes as '___E'. This supports any type digest
                            code of either 1, 2 or 4 characters.
        code (str): qb64 digest code shared by all node/leaf SAIDs
        nodes (dict): indexed by SAID of each node
                      to be modified with virtual interface
                      that supports either in-memory and disk based storage
        leaves (dict): indexed by SAID of each leaf

    """
    Code = MtrDex.Blake3_256  # tree wide default SAID code for parts
    Dummy = '#'  # default dummy for computing SAIDS

    @classmethod
    def saidify(cls, saidage, label=None, code=None):
        """Computes and returns saidified copy of namedtuple data where said
        is always inserted field given by label. When label is None then
        defaults to first field

            Parameters:


        Eventually when we have a Structor subclass with group code we can
        use a Structor instance to calculate the said
        """
        code = code if code is not None else cls.Code
        size = Noncer._fullSize(code)
        dummy = cls.Dummy * size
        label = label if label is not None else saidage._fields[0]
        rkwa = dict()
        rkwa[label] = dummy
        saidage = saidage._replace(**rkwa)  # replace said field at label with dummy

        ser = "".join(saidage)  # concat fields in tuple
        said = Diger(ser=ser.encode(), code=code).qb64  # convert ser to bytes
        rkwa[label] = said
        return saidage._replace(**rkwa)



    def __init__(self, tuid=None, verdig=None, major=0, minor=0,
                 code=None, **kwa):
        """Initialize instance

        Parameters::
            tuid (str|bytes|None): qb64 or qb64b of 16 byte tree unique identifier.
                                   None means generate crypto strength value.
            verdig (str|None): qb64 encoded Tagger instance version + tree wide digest
                            code. None means use major, minor, code to generate
            major (int): major version value [0..63] to be encoded as one Base64 char
            minor (int): minor version value [0..4095] to be encoded as two Base64 chars
            code (str|bytes): tree wide digest code (qb64 or qb64b) for saids


        """
        self.tuid = Noncer(nonce=tuid).qb64b
        if verdig is not None:
            if len(verdig) != 8:
                raise ValueError(f"Invalid {verdig=}")
            self.verdig = Tagger(qb64=verdig).qb64  # apply Tagger validation

        else:
            if major < 0 or major > 63:
                raise ValueError(f"Invalid {major=} not [0-63]")
            major = intToB64(major, l=1)

            if minor < 0 or minor > 495:
                raise ValueError(f"Invalid {minor=} not [0-4095]")
            minor = intToB64(minor, l=2)

            code = code if code is not None else self.Code
            if hasattr(code, "decode"):
                code = code.decode()  # convert bytes to str
            if code not in DigDex:
                raise ValueError(f"Invalid {code=}")

            tag = major + minor + code.rjust(4, "_")
            self.verdig = Tagger(tag=tag).qb64

        self.code = self.verdig[3:].lstrip("_")  # get unpadded code

        rheight = Number(num=MaxHeight).qb64  # root height always 256 cesr encode
        rhqb64 = rnumber.qb64
        rhqb2 = rnumber.qb2

        # root limb always encoded 32 bytes or 256 bits of zeros
        rlimb = Diger(raw=bytes(MaxLimbLenBytes), code=self.code)
        rpqb64 = rlimb.qb64
        rpqb2 = rlimb.qb2

        childempty = Noncer(nonce="")  # creates cesr encoded empty NonceDex.Empty
        ceqb64 = childempty.qb64
        ceqb2 = childempty.qb2

        # qb64 encoded to compute said
        #rootFull = NodageFull(tuid=self.tuid,
                              #verdig=self.verdig,
                              #height=rhqb64,
                              #path=rpqb64,
                              #left=ceqb64,
                              #right=ceqb64)

        # replace rootFull with SAIDed copy
        rootFull = self.saidify(saidage=rootFull, label="said", code=self.code)
        rsqb64 = rootFull.said
        rsaid = Diger(qb64=rsqb64)
        rsqb2 = rsaid.qb2

        # empty root as compact per node only qb2 values with empty children
        self.root = Nodage(said=rsqb2, height=rhqb2, limb=rpqb2, left=ceqb2, right=ceqb2)

        self.nodes = dict()  # indexed by qb2 of node said
        self.nodes[self.root.said] = self.root  # compact namedtuple with qb2 values


class SiterOld:
    """Siter manages a SAIDed Info Tree (SIT)


    Attributes::
        tuid (str): qb64 of tree unique idendifier (TUID) that is CESR encoded
                    16 byte unique value for tree. This ensures separation of
                    digests within each unique tree. Use Noncer to encode/decode
        verdig (str): qb64 encoded 8 char code + 3 char tree version + 4 char
                       tree wide digest code
                        First char is major version as one Base64 char (0-63)
                        Next two characters are minor version as two Base64 chars (0-4095)
                        Last 4 chars are '_' prefixed digest code.
                            'E' encodes as '___E'. This supports any type digest
                            code of either 1, 2 or 4 characters.
        code (str): qb64 digest code shared by all node/leaf SAIDs
        nodes (dict): indexed by SAID of each node
                      to be modified with virtual interface
                      that supports either in-memory and disk based storage
        leaves (dict): indexed by SAID of each leaf

    """
    Code = MtrDex.Blake3_256  # tree wide default SAID code for parts
    Dummy = '#'  # default dummy for computing SAIDS

    @classmethod
    def saidify(cls, data, label=None, code=None):
        """Computes and returns saidified copy of namedtuple data where said
        is always inserted field given by label. When label is None then
        defaults to first field

            Parameters:


        Eventually when we have a Structor subclass with group code we can
        use a Structor instance to calculate the said
        """
        code = code if code is not None else cls.Code
        size = Noncer._fullSize(code)
        dummy = cls.Dummy * size
        label = label if label is not None else data._fields[0]
        rkwa = dict()
        rkwa[label] = dummy
        data = data._replace(**rkwa)  # replace said field at label with dummy

        ser = "".join(data)  # concat fields in tuple
        said = Diger(ser=ser.encode(), code=code).qb64  # convert ser to bytes
        rkwa[label] = said
        return data._replace(**rkwa)



    def __init__(self, tuid=None, verdig=None, major=0, minor=0,
                 code=None, **kwa):
        """Initialize instance

        Parameters::
            tuid (str|bytes|None): qb64 or qb64b of 16 byte tree unique identifier.
                                   None means generate crypto strength value.
            verdig (str|None): qb64 encoded Tagger instance version + tree wide digest
                            code. None means use major, minor, code to generate
            major (int): major version value [0..63] to be encoded as one Base64 char
            minor (int): minor version value [0..4095] to be encoded as two Base64 chars
            code (str|bytes): tree wide digest code (qb64 or qb64b) for saids


        """
        self.tuid = Noncer(nonce=tuid).qb64b
        if verdig is not None:
            if len(verdig) != 8:
                raise ValueError(f"Invalid {verdig=}")
            self.verdig = Tagger(qb64=verdig).qb64  # apply Tagger validation

        else:
            if major < 0 or major > 63:
                raise ValueError(f"Invalid {major=} not [0-63]")
            major = intToB64(major, l=1)

            if minor < 0 or minor > 495:
                raise ValueError(f"Invalid {minor=} not [0-4095]")
            minor = intToB64(minor, l=2)

            code = code if code is not None else self.Code
            if hasattr(code, "decode"):
                code = code.decode()  # convert bytes to str
            if code not in DigDex:
                raise ValueError(f"Invalid {code=}")

            tag = major + minor + code.rjust(4, "_")
            self.verdig = Tagger(tag=tag).qb64

        self.code = self.verdig[3:].lstrip("_")  # get unpadded code

        rheight = Number(num=MaxHeight).qb64  # root height always 256 cesr encode
        rhqb64 = rnumber.qb64
        rhqb2 = rnumber.qb2

        # root path always encoded 32 bytes or 256 bits of zeros
        rpath = Diger(raw=bytes(MaxLimbLenBytes), code=self.code)
        rpqb64 = rpath.qb64
        rpqb2 = rpath.qb2

        childempty = Noncer(nonce="")  # creates cesr encoded empty NonceDex.Empty
        ceqb64 = childempty.qb64
        ceqb2 = childempty.qb2

        # qb64 encoded to compute said
        rootFull = NodageFull(tuid=self.tuid,
                              verdig=self.verdig,
                              height=rhqb64,
                              path=rpqb64,
                              left=ceqb64,
                              right=ceqb64)

        # replace rootFull with SAIDed copy
        rootFull = self.saidify(data=rootFull, label="said", code=self.code)
        rsqb64 = rootFull.said
        rsaid = Diger(qb64=rsqb64)
        rsqb2 = rsaid.qb2

        # empty root as compact per node only qb2 values with empty children
        self.root = Nodage(said=rsqb2, height=rhqb2, path=rpqb2, left=ceqb2, right=ceqb2)

        self.nodes = dict()  # indexed by qb2 of node said
        self.nodes[self.root.said] = self.root  # compact namedtuple with qb2 values


