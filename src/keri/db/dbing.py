# -*- encoding: utf-8 -*-
"""
keri.db.dbing module


import lmdb
db = lmdb.open("/tmp/keri_db_setup_test")
db.max_key_size()
511

# create named dbs  (core and tables)
    gDbEnv.open_db(b'core')
    gDbEnv.open_db(b'hid2did')  # table of dids keyed by hids
    gDbEnv.open_db(b'did2offer', dupsort=True)  # table of offer expirations keyed by offer relative dids
    gDbEnv.open_db(b'anon', dupsort=True)  # anonymous messages
    gDbEnv.open_db(b'expire2uid', dupsort=True)  # expiration to uid anon

The dupsort, integerkey, integerdup, and dupfixed parameters are ignored
if the database already exists.
The state of those settings are persistent and immutable per database.
See _Database.flags() to view the state of those options for an opened database.
A consequence of the immutability of these flags is that the default non-named
database will never have these flags set.

So only need to set dupsort first time opened each other opening does not
need to call it


May want to use buffers for reads of immutable serializations such as events
and sigs. Anything not read modify write but read only.

"{:032x}".format(1024)
'00000000000000000000000000000400'

h = ["00", "01", "02", "0a", "0f", "10", "1a", "11", "1f", "f0", "a0"]
h.sort()
h
['00', '01', '02', '0a', '0f', '10', '11', '1a', '1f', 'a0', 'f0']

l
['a', 'aa', 'b', 'ba', 'aaa', 'baa']
l.sort()
l
['a', 'aa', 'aaa', 'b', 'ba', 'baa']

"""
import os
import shutil
import tempfile
import stat

from contextlib import contextmanager

import lmdb

try:
    import simplejson as json
except ImportError:
    import json

from hio.base import doing

from  ..kering import KeriError


class DatabaseError(KeriError):
    """
    Database related errors
    Usage:
        raise DatabaseError("error message")
    """

ProemSize =  33
MaxProem = int("f"*(ProemSize-1), 16)


def dgKey(pre, dig):
    """
    Returns bytes DB key from concatenation of qualified Base64 prefix
    bytes pre and qualified Base64 bytes digest of serialized event
    If pre or dig are str then converts to bytes
    """
    if hasattr(pre, "encode"):
        pre = pre.encode("utf-8")  # convert str to bytes
    if hasattr(dig, "encode"):
        dig = dig.encode("utf-8")  # convert str to bytes

    return (b'%s.%s' %  (pre, dig))


def snKey(pre, sn):
    """
    Returns bytes DB key from concatenation of qualified Base64 prefix
    bytes pre and int sn (sequence number) of event
    """
    if hasattr(pre, "encode"):
        pre = pre.encode("utf-8")  # convert str to bytes
    return (b'%s.%032x' % (pre, sn))


def splitKey(key):
    """
    Returns duple of pre and either dig or sn str by splitting key at '.'
    Accepts either bytes or str key
    Raises ValueError if key does not split into exactly two elements
    """
    if isinstance(key, memoryview):
        key = bytes(key)
    if hasattr(key, "encode"):
        sep = "."
    else:
        sep = b'.'
    splits = key.split(sep)
    if len(splits) != 2:
        raise  ValueError("Unsplitable key = {}".format(key))
    return tuple(splits)


def splitKeySn(key):
    """
    Returns list of pre and int sn from key
    Accepts either bytes or str key

    """
    if isinstance(key, memoryview):
        key = bytes(key)
    pre, sn = splitKey(key)
    sn = int(sn, 16)
    return (pre, sn)


def clearDatabaserDir(path):
    """
    Remove directory path
    """
    if os.path.exists(path):
        shutil.rmtree(path)


@contextmanager
def openLMDB(cls=None, name="test", temp=True, **kwa):
    """
    Context manager wrapper LMDBer instances.
    Defaults to temporary databases.
    Context 'with' statements call .close on exit of 'with' block

    Parameters:
        cls is Class instance of subclass instance
        name is str name of LMDBer dirPath so can have multiple databasers
             at different directory path names thar each use different name
        temp is Boolean, True means open in temporary directory, clear on close
                        Otherwise open in persistent directory, do not clear on close

    Usage:

    with openDatabaser(name="gen1") as baser1:
        baser1.env  ....

    with openDatabaser(name="gen2, cls=Baser)

    """
    if cls is None:
        cls = LMDBer
    try:
        lmdber = cls(name=name, temp=temp, reopen=True, **kwa)
        yield lmdber

    finally:
        lmdber.close()


class LMDBer:
    """
    LBDBer base class for LMDB manager instances.
    Creates a specific instance of an LMDB database directory and environment.

    Attributes:
        .name is LMDB database name did2offer
        .temp is Boolean, True means open db in /tmp directory
        .headDirPath is head directory path for db
        .mode is numeric os dir permissions for db directory
        .path is LMDB main (super) database directory path
        .env is LMDB main (super) database environment
        .opened is Boolean, True means LMDB .env at .path is opened.
                            Otherwise LMDB .env is closed

    Properties:


    """
    HeadDirPath = "/usr/local/var"  # default in /usr/local/var
    TailDirPath = "keri/db"
    AltHeadDirPath = "~"  #  put in ~ as fallback when desired not permitted
    AltTailDirPath = ".keri/db"
    TempHeadDir = "/tmp"
    TempPrefix = "keri_lmdb_"
    TempSuffix = "_test"
    MaxNamedDBs = 16

    def __init__(self, name='main', temp=False, headDirPath=None, dirMode=None,
                 reopen=True):
        """
        Setup main database directory at .dirpath.
        Create main database environment at .env using .dirpath.

        Parameters:
            name is str directory path name differentiator for main database
                When system employs more than one keri database, name allows
                differentiating each instance by name
            temp is boolean, assign to .temp
                True then open in temporary directory, clear on close
                Othewise then open persistent directory, do not clear on close
            headDirPath is optional str head directory pathname for main database
                If not provided use default .HeadDirpath
            dirMode is int numeric os dir permissions for database directory
                default is use os defaults and not set the dirMode
            reopen is boolean, IF True then database will be reopened by this init

        """
        self.name = name
        self.temp = True if temp else False
        self.headDirPath = headDirPath
        self.dirMode = dirMode
        self.path = None
        self.env = None
        self.opened = False

        if reopen:
            self.reopen(headDirPath=self.headDirPath, dirMode=dirMode)


    def reopen(self, temp=None, headDirPath=None, dirMode=None):
        """
        Use or Create if not preexistent, directory path for lmdb at .path
        Open lmdb and assign to .env

        Parameters:
            temp is optional boolean:
                If None ignore Otherwise
                    Assign to .temp
                    If True then open temporary directory, clear on close
                    If False then open persistent directory, do not clear on close
            headDirPath is optional str head directory pathname of main database
                If not provided use default .HeadDirpath
        """
        if temp is not None:
            self.temp = True if temp else False  # need .temp for clear on .close

        if headDirPath is None:
            headDirPath = self.headDirPath

        if dirMode is None:
            dirMode = self.dirMode

        if self.temp:
            headDirPath = tempfile.mkdtemp(prefix=self.TempPrefix,
                                           suffix=self.TempSuffix,
                                           dir=self.TempHeadDir)
            self.path = os.path.abspath(
                                os.path.join(headDirPath,
                                             self.TailDirPath,
                                             self.name))
            os.makedirs(self.path)

        else:
            if not headDirPath:
                headDirPath = self.HeadDirPath

            self.path = os.path.abspath(
                                os.path.expanduser(
                                    os.path.join(headDirPath,
                                                 self.TailDirPath,
                                                 self.name)))

            if not os.path.exists(self.path):
                try:
                    os.makedirs(self.path)
                except OSError as ex:
                    headDirPath = self.AltHeadDirPath
                    self.path = os.path.abspath(
                                        os.path.expanduser(
                                            os.path.join(headDirPath,
                                                         self.AltTailDirPath,
                                                         self.name)))
                    if not os.path.exists(self.path):
                        os.makedirs(self.path)
            else:
                if not os.access(self.path, os.R_OK | os.W_OK):
                    headDirPath = self.AltHeadDirPath
                    self.path = os.path.abspath(
                                        os.path.expanduser(
                                            os.path.join(headDirPath,
                                                         self.AltTailDirPath,
                                                         self.name)))
                    if not os.path.exists(self.path):
                        os.makedirs(self.path)

            if dirMode is not None:  # set mode if mode and not temp
                os.chmod(self.path, dirMode)

        # open lmdb major database instance
        # creates files data.mdb and lock.mdb in .dbDirPath
        self.env = lmdb.open(self.path, max_dbs=self.MaxNamedDBs)
        self.opened = True


    def close(self, clear=False):
        """
        Close lmdb at .env and if clear or .temp then remove lmdb directory at .path
        Parameters:
           clear is boolean, True means clear lmdb directory
        """
        if self.env:
            try:
                self.env.close()
            except:
                pass

        self.env = None
        self.opened = False

        if clear or self.temp:
            self.clearDirPath()


    def clearDirPath(self):
        """
        Remove lmdb directory at .path
        """
        if os.path.exists(self.path):
            shutil.rmtree(self.path)


    def putVal(self, db, key, val):
        """
        Write serialized bytes val to location key in db
        Does not overwrite.
        Returns True If val successfully written Else False
        Returns False if val at key already exitss

        Parameters:
            db is opened named sub db with dupsort=False
            key is bytes of key within sub db's keyspace
            val is bytes of value to be written
        """
        with self.env.begin(db=db, write=True, buffers=True) as txn:
            return (txn.put(key, val, overwrite=False))


    def setVal(self, db, key, val):
        """
        Write serialized bytes val to location key in db
        Overwrites existing val if any
        Returns True If val successfully written Else False

        Parameters:
            db is opened named sub db with dupsort=False
            key is bytes of key within sub db's keyspace
            val is bytes of value to be written
        """
        with self.env.begin(db=db, write=True, buffers=True) as txn:
            return (txn.put(key, val))


    def getVal(self, db, key):
        """
        Return val at key in db
        Returns None if no entry at key

        Parameters:
            db is opened named sub db with dupsort=False
            key is bytes of key within sub db's keyspace

        """
        with self.env.begin(db=db, write=False, buffers=True) as txn:
            return( txn.get(key))


    def delVal(self, db, key):
        """
        Deletes value at key in db.
        Returns True If key exists in database Else False

        Parameters:
            db is opened named sub db with dupsort=False
            key is bytes of key within sub db's keyspace
        """
        with self.env.begin(db=db, write=True, buffers=True) as txn:
            return (txn.delete(key))


    def putVals(self, db, key, vals):
        """
        Write each entry from list of bytes vals to key in db
        Adds to existing values at key if any
        Returns True If only one first written val in vals Else False
        Apparently always returns True (is this how .put works with dupsort=True)

        Duplicates are inserted in lexocographic order not insertion order.
        Lmdb does not insert a duplicate unless it is a unique value for that
        key.

        Parameters:
            db is opened named sub db with dupsort=False
            key is bytes of key within sub db's keyspace
            vals is list of bytes of values to be written
        """
        with self.env.begin(db=db, write=True, buffers=True) as txn:
            result = True
            for val in vals:
                result = result and txn.put(key, val, dupdata=True)
            return result


    def addVal(self, db, key, val):
        """
        Add val bytes as dup to key in db
        Adds to existing values at key if any
        Returns True if written else False if dup val already exists

        Duplicates are inserted in lexocographic order not insertion order.
        Lmdb does not insert a duplicate unless it is a unique value for that
        key.

        Does inclusion test to dectect of duplicate already exists
        Uses a python set for the duplicate inclusion test. Set inclusion scales
        with O(1) whereas list inclusion scales with O(n).

        Parameters:
            db is opened named sub db with dupsort=False
            key is bytes of key within sub db's keyspace
            val is bytes of value to be written
        """
        dups = set(self.getVals(db, key))  #get preexisting dups if any
        result = False
        if val not in dups:
            with self.env.begin(db=db, write=True, buffers=True) as txn:
                result = txn.put(key, val, dupdata=True)
        return result


    def getVals(self, db, key):
        """
        Return list of values at key in db
        Returns empty list if no entry at key

        Duplicates are retrieved in lexocographic order not insertion order.

        Parameters:
            db is opened named sub db with dupsort=True
            key is bytes of key within sub db's keyspace
        """

        with self.env.begin(db=db, write=False, buffers=True) as txn:
            cursor = txn.cursor()
            vals = []
            if cursor.set_key(key):  # moves to first_dup
                vals = [val for val in cursor.iternext_dup()]
            return vals

    def getValsIter(self, db, key):
        """
        Return iterator of all dup values at key in db
        Raises StopIteration error when done or if empty

        Duplicates are retrieved in lexocographic order not insertion order.

        Parameters:
            db is opened named sub db with dupsort=True
            key is bytes of key within sub db's keyspace
        """
        with self.env.begin(db=db, write=False, buffers=True) as txn:
            cursor = txn.cursor()
            vals = []
            if cursor.set_key(key):  # moves to first_dup
                for val in cursor.iternext_dup():
                    yield val


    def cntVals(self, db, key):
        """
        Return count of dup values at key in db, or zero otherwise

        Parameters:
            db is opened named sub db with dupsort=True
            key is bytes of key within sub db's keyspace
        """
        with self.env.begin(db=db, write=False, buffers=True) as txn:
            cursor = txn.cursor()
            count = 0
            if cursor.set_key(key):  # moves to first_dup
                count = cursor.count()
            return count


    def delVals(self, db, key, val=b''):
        """
        Deletes all values at key in db if val=b'' else deletes the dup
        that equals val
        Returns True If key (and val if not empty) exists in db Else False

        Parameters:
            db is opened named sub db with dupsort=True
            key is bytes of key within sub db's keyspace
            val is bytes of dup val at key to delete
        """
        with self.env.begin(db=db, write=True, buffers=True) as txn:
            return (txn.delete(key, val))


    def putIoVals(self, db, key, vals):
        """
        Write each entry from list of bytes vals to key in db in insertion order
        Adds to existing values at key if any
        Returns True If at least one of vals is added as dup, False otherwise
        Assumes DB opened with dupsort=True

        Duplicates at a given key preserve insertion order of duplicate.
        Because lmdb is lexocographic an insertion ordering proem is prepended to
        all values that makes lexocographic order that same as insertion order
        Duplicates are ordered as a pair of key plus value so prepending proem
        to each value changes duplicate ordering. Proem is 33 characters long.
        With 32 character hex string followed by '.' for essentiall unlimited
        number of values which will be limited by memory.
        With prepended proem ordinal must explicity check for duplicate values
        before insertion. Uses a python set for the duplicate inclusion test.
        Set inclusion scales with O(1) whereas list inclusion scales with O(n).

        Parameters:
            db is opened named sub db with dupsort=False
            key is bytes of key within sub db's keyspace
            vals is list of bytes of values to be written
        """

        result = False
        dups = set(self.getIoVals(db, key))  #get preexisting dups if any
        with self.env.begin(db=db, write=True, buffers=True) as txn:
            idx = 0
            cursor = txn.cursor()
            if cursor.set_key(key): # move to key if any
                if cursor.last_dup(): # move to last dup
                    idx = 1 + int(bytes(cursor.value()[:32]), 16)  # get last index as int

            for val in vals:
                if val not in dups:
                    val = (b'%032x.' % (idx)) +  val  # prepend ordering proem
                    txn.put(key, val, dupdata=True)
                    idx += 1
                    result = True
        return result


    def addIoVal(self, db, key, val):
        """
        Add val bytes as dup in insertion order to key in db
        Adds to existing values at key if any
        Returns True if written else False if val is already a dup
        Actual value written include prepended proem ordinal
        Assumes DB opened with dupsort=True

        Parameters:
            db is opened named sub db with dupsort=False
            key is bytes of key within sub db's keyspace
            val is bytes of value to be written
        """
        return self.putIoVals(db, key, [val])


    def getIoVals(self, db, key):
        """
        Return list of duplicate values at key in db in insertion order
        Returns empty list if no entry at key
        Removes prepended proem ordinal from each val  before returning
        Assumes DB opened with dupsort=True

        Parameters:
            db is opened named sub db with dupsort=True
            key is bytes of key within sub db's keyspace
        """

        with self.env.begin(db=db, write=False, buffers=True) as txn:
            cursor = txn.cursor()
            vals = []
            if cursor.set_key(key):  # moves to first_dup
                # slice off prepended ordering proem
                vals = [val[33:] for val in cursor.iternext_dup()]
            return vals


    def getIoValsIter(self, db, key):
        """
        Return iterator of all duplicate values at key in db in insertion order
        Raises StopIteration Error when no remaining dup items = empty.
        Removes prepended proem ordinal from each val before returning
        Assumes DB opened with dupsort=True

        Parameters:
            db is opened named sub db with dupsort=True
            key is bytes of key within sub db's keyspace
        """

        with self.env.begin(db=db, write=False, buffers=True) as txn:
            cursor = txn.cursor()
            vals = []
            if cursor.set_key(key):  # moves to first_dup
                for val in cursor.iternext_dup():
                    yield val[33:]  # slice off prepended ordering proem


    def getIoValLast(self, db, key):
        """
        Return last added dup value at key in db in insertion order
        Returns None no entry at key
        Removes prepended proem ordinal from val before returning
        Assumes DB opened with dupsort=True

        Parameters:
            db is opened named sub db with dupsort=True
            key is bytes of key within sub db's keyspace
        """

        with self.env.begin(db=db, write=False, buffers=True) as txn:
            cursor = txn.cursor()
            val = None
            if cursor.set_key(key):  # move to first_dup
                if cursor.last_dup(): # move to last_dup
                    val = cursor.value()[33:]  # slice off prepended ordering proem
            return val


    def getIoItemsNext(self, db, key=b"", skip=True):
        """
        Return list of all dup items at next key after key in db in insertion order.
        Item is (key, val) with proem stripped from val stored in db.
        If key == b'' then returns list of dup items at first key in db.
        If skip is False and key is not empty then returns dup items at key
        Returns empty list if no entries at next key after key

        If key is empty then gets io items (key, io value) at first key in db
        Use the return key from items as next key for next call to function in
        order to iterate through the database

        Assumes DB opened with dupsort=True

        Parameters:
            db is opened named sub db with dupsort=True
            key is bytes of key within sub db's keyspace or empty string
            skip is Boolean If True skips to next key if key is not empty string
                    Othewise don't skip for first pass
        """

        with self.env.begin(db=db, write=False, buffers=True) as txn:
            cursor = txn.cursor()
            items = []
            if cursor.set_range(key):  # moves to first_dup at key
                found = True
                if skip and key and cursor.key() == key:  # skip to next key
                    found = cursor.next_nodup()  # skip to next key not dup if any
                if found:
                    # slice off prepended ordering prefix on value in item
                    items = [(key, val[33:]) for key, val in cursor.iternext_dup(keys=True)]
            return items


    def getIoItemsNextIter(self, db, key=b"", skip=True):
        """
        Return iterator of all dup items at next key after key in db in insertion order.
        Item is (key, val) with proem stripped from val stored in db.
        If key = b'' then returns list of dup items at first key in db.
        If skip is False and key is not empty then returns dup items at key
        Raises StopIteration Error when no remaining dup items = empty.

        If key is empty then gets io items (key, io value) at first key in db
        Use the return key from items as next key for next call to function in
        order to iterate through the database

        Assumes DB opened with dupsort=True

        Parameters:
            db is opened named sub db with dupsort=True
            key is bytes of key within sub db's keyspace or empty
            skip is Boolean If True skips to next key if key is not empty string
                    Othewise don't skip for first pass
        """

        with self.env.begin(db=db, write=False, buffers=True) as txn:
            cursor = txn.cursor()
            if cursor.set_range(key):  # moves to first_dup at key
                found = True
                if skip and key and cursor.key() == key:  # skip to next key
                    found = cursor.next_nodup()  # skip to next key not dup if any
                if found:
                    for key, val in cursor.iternext_dup(keys=True):
                        yield (key, val[33:]) # slice off prepended ordering prefix


    def cntIoVals(self, db, key):
        """
        Return count of dup values at key in db, or zero otherwise
        Assumes DB opened with dupsort=True

        Parameters:
            db is opened named sub db with dupsort=True
            key is bytes of key within sub db's keyspace
        """

        with self.env.begin(db=db, write=False, buffers=True) as txn:
            cursor = txn.cursor()
            count = 0
            if cursor.set_key(key):  # moves to first_dup
                count = cursor.count()
            return count


    def delIoVals(self,db, key):
        """
        Deletes all values at key in db if key present.
        Returns True If key exists and dups deleted Else False
        Assumes DB opened with dupsort=True

        Parameters:
            db is opened named sub db with dupsort=True
            key is bytes of key within sub db's keyspace
        """

        with self.env.begin(db=db, write=True, buffers=True) as txn:
            return (txn.delete(key))


    def delIoVal(self, db, key, val):
        """
        Deletes dup io val at key in db. Performs strip search to find match.
        Strips proems and then searches.
        Returns True if delete else False if val not present
        Assumes DB opened with dupsort=True

        Duplicates at a given key preserve insertion order of duplicate.
        Because lmdb is lexocographic an insertion ordering proem is prepended to
        all values that makes lexocographic order that same as insertion order
        Duplicates are ordered as a pair of key plus value so prepending proem
        to each value changes duplicate ordering. Proem is 33 characters long.
        With 32 character hex string followed by '.' for essentially unlimited
        number of values which will be limited by memory.

        Does a linear search so not very efficient when not deleting from the front.
        This is hack for supporting escrow which needs to delete individual dup.
        The problem is that escrow is not fixed buts stuffs gets added and
        deleted which just adds to the value of the proem. 2**16 is an impossibly
        large number so the proem will not max out practically. But its not
        and elegant solution. So maybe escrows need to use a different approach.
        But really didn't want to add another database just for escrows.

        Parameters:
            db is opened named sub db with dupsort=False
            key is bytes of key within sub db's keyspace
            val is bytes of value to be deleted without intersion ordering proem
        """

        with self.env.begin(db=db, write=True, buffers=True) as txn:
            cursor = txn.cursor()
            if cursor.set_key(key):  # move to first_dup
                for proval in cursor.iternext_dup():  #  value with proem
                    if val == proval[33:]:  #  strip of proem
                        return cursor.delete()
        return False


    def getIoValsAllPreIter(self, db, pre):
        """
        Returns iterator of all dup vals in insertion order for all entries
        with same prefix across all sequence numbers in order without gaps
        starting with zero. Stops if gap or different pre.
        Assumes that key is combination of prefix and sequence number given
        by .snKey().
        Removes prepended proem ordinal from each val before returning

        Raises StopIteration Error when empty.

        Duplicates are retrieved in insertion order.

        Parameters:
            db is opened named sub db with dupsort=True
            pre is bytes of itdentifier prefix prepended to sn in key
                within sub db's keyspace
        """
        with self.env.begin(db=db, write=False, buffers=True) as txn:
            cursor = txn.cursor()
            key = snKey(pre, cnt:=0)
            while cursor.set_key(key):  # moves to first_dup
                for val in cursor.iternext_dup():
                    # slice off prepended ordering prefix
                    yield val[33:]
                key = snKey(pre, cnt:=cnt+1)


    def getIoValLastAllPreIter(self, db, pre):
        """
        Returns iterator of last only of dup vals of each key in insertion order
        for all entries with same prefix across all sequence numbers in order
        without gaps starting with zero. Stops if gap or different pre.
        Assumes that key is combination of prefix and sequence number given
        by .snKey().
        Removes prepended proem ordinal from each val before returning

        Raises StopIteration Error when empty.

        Duplicates are retrieved in insertion order.


        Parameters:
            db is opened named sub db with dupsort=True
            pre is bytes of itdentifier prefix prepended to sn in key
                within sub db's keyspace
        """
        with self.env.begin(db=db, write=False, buffers=True) as txn:
            cursor = txn.cursor()
            key = snKey(pre, cnt:=0)
            while cursor.set_key(key):  # moves to first_dup
                if cursor.last_dup(): # move to last_dup
                    yield cursor.value()[33:]  # slice off prepended ordering prefix
                key = snKey(pre, cnt:=cnt+1)


    def getIoValsAnyPreIter(self, db, pre):
        """
        Returns iterator of all dup vals in insertion order for any entries
        with same prefix across all sequence numbers in order including gaps.
        Stops when pre is different.
        Assumes that key is combination of prefix and sequence number given
        by .snKey().
        Removes prepended proem ordinal from each val before returning

        Raises StopIteration Error when empty.

        Duplicates are retrieved in insertion order.
        Because lmdb is lexocographic an insertion ordering proem is prepended to
        all values that makes lexocographic order that same as insertion order
        Duplicates are ordered as a pair of key plus value so prepending prefix
        to each value changes duplicate ordering. Proem is 17 characters long.
        With 16 character hex string followed by '.'.

        Parameters:
            db is opened named sub db with dupsort=True
            pre is bytes of itdentifier prefix prepended to sn in key
                within sub db's keyspace
        """
        with self.env.begin(db=db, write=False, buffers=True) as txn:
            cursor = txn.cursor()
            key = snKey(pre, cnt:=0)
            while cursor.set_range(key):  #  moves to first dup of key >= key
                key = cursor.key()  # actual key
                front, back = bytes(key).split(sep=b'.', maxsplit=1)
                if front != pre:
                    break
                for val in cursor.iternext_dup():
                    yield val[33:]  # slice off prepended ordering prefix
                cnt = int(back, 16)
                key = snKey(pre, cnt:=cnt+1)



def openDB(name="test", **kwa):
    """
    Returns contextmanager generated by openLMDB but with Baser instance
    """
    return openLMDB(cls=Baser, name=name, **kwa)


class Baser(LMDBer):
    """
    Baser sets up named sub databases with Keri Event Logs within main database

    Attributes:
        see superclass LMDBer for inherited attributes

        .evts is named sub DB whose values are serialized events
            dgKey
            DB is keyed by identifer prefix plus digest of serialized event
            Only one value per DB key is allowed

        .dtss is named sub DB of datetime stamp strings in ISO 8601 format of
            dgKey
            the datetime when the event was first seen by log.
            Used for escrows timeouts and extended validation.
            DB is keyed by identifer prefix plus digest of serialized event

        .sigs is named sub DB of fully qualified event signatures
            dgKey
            DB is keyed by identifer prefix plus digest of serialized event
            More than one value per DB key is allowed

        .rcts is named sub DB of event receipt couplets from nontransferable
            signers. Each couplet is concatenation of fully qualified
            non-transferale prefix plus fully qualified event signature
            by witness, watcher, or validator.
            dgKey
            SB is keyed by identifer prefix plus digest of serialized event
            More than one value per DB key is allowed

        .ures is named sub DB of unverified event receipt escrowed triples from
            non-transferable signers. Each triplet is concatenation of fully
            qualified receipted event digest, non-transferable event identfier prefix,
            plus receipt event signature by witness, watcher, or validator
            snKey
            SB is keyed by receipted event controller prefix plus sn
            of serialized event
            More than one value per DB key is allowed

        .vrcs is named sub DB of event validator receipt quadlets from transferable
            signers. Each quadlet is concatenation of  four fully qualified items
            of validator. These are transferable prefix, plus latest establishment
            event sequence number plus latest establishment event digest,
            plus event signature.
            When latest establishment event is multisig then there will
            be multiple quadlets one per signing key, each a dup at same db key.
            dgKey
            SB is keyed by identifer prefix plus digest of serialized event
            More than one value per DB key is allowed

        .vres is named sub DB of unverified event validator receipt escrowed
            quadlets from transferable signers. Each quadlet is concatenation of
            four fully qualified items  of validator. These are transferable prefix,
            plus latest establishment event sequence number plus latest
            establishment event digest, plus event signature.
            When latest establishment event is multisig then there will
            be multiple quadlets one per signing key, each a dup at same db key.
            dgKey
            SB is keyed by identifer prefix plus digest of serialized event
            More than one value per DB key is allowed

        .kels is named sub DB of key event log tables that map sequence numbers
            to serialized event digests.
            snKey
            Values are digests used to lookup event in .evts sub DB
            DB is keyed by identifer prefix plus sequence number of key event
            More than one value per DB key is allowed

        .pses is named sub DB of partially signed escrowed event tables
            that map sequence numbers to serialized event digests.
            snKey
            Values are digests used to lookup event in .evts sub DB
            DB is keyed by identifer prefix plus sequence number of key event
            More than one value per DB key is allowed

        .ooes is named sub DB of out of order escrowed event tables
            that map sequence numbers to serialized event digests.
            snKey
            Values are digests used to lookup event in .evts sub DB
            DB is keyed by identifer prefix plus sequence number of key event
            More than one value per DB key is allowed

        .dels is named sub DB of deplicitous event log tables that map sequence numbers
            to serialized event digests.
            snKey
            Values are digests used to lookup event in .evts sub DB
            DB is keyed by identifer prefix plus sequence number of key event
            More than one value per DB key is allowed

        .ldes is named sub DB of likely deplicitous escrowed event tables
            that map sequence numbers to serialized event digests.
            snKey
            Values are digests used to lookup event in .evts sub DB
            DB is keyed by identifer prefix plus sequence number of key event
            More than one value per DB key is allowed


    Properties:


    """
    def __init__(self, headDirPath=None, reopen=True, **kwa):
        """
        Setup named sub databases.

        Inherited Parameters:
            name is str directory path name differentiator for main database
                When system employs more than one keri database, name allows
                differentiating each instance by name
            temp is boolean, assign to .temp
                True then open in temporary directory, clear on close
                Othewise then open persistent directory, do not clear on close
            headDirPath is optional str head directory pathname for main database
                If not provided use default .HeadDirpath
            mode is int numeric os dir permissions for database directory
            reopen is boolean, IF True then database will be reopened by this init

        Notes:

        dupsort=True for sub DB means allow unique (key,pair) duplicates at a key.
        Duplicate means that is more than one value at a key but not a redundant
        copies a (key,value) pair per key. In other words the pair (key,value)
        must be unique both key and value in combination.
        Attempting to put the same (key,value) pair a second time does
        not add another copy.

        Duplicates are inserted in lexocographic order by value, insertion order.

        """
        super(Baser, self).__init__(headDirPath=headDirPath, reopen=reopen, **kwa)


    def reopen(self, **kwa):
        """
        Open sub databases
        """
        super(Baser, self).reopen(**kwa)

        # Create by opening first time named sub DBs within main DB instance
        # Names end with "." as sub DB name must include a non Base64 character
        # to avoid namespace collisions with Base64 identifier prefixes.

        self.evts = self.env.open_db(key=b'evts.')
        self.dtss = self.env.open_db(key=b'dtss.')
        self.sigs = self.env.open_db(key=b'sigs.', dupsort=True)
        self.rcts = self.env.open_db(key=b'rcts.', dupsort=True)
        self.ures = self.env.open_db(key=b'ures.', dupsort=True)
        self.vrcs = self.env.open_db(key=b'vrcs.', dupsort=True)
        self.vres = self.env.open_db(key=b'vres.', dupsort=True)
        self.kels = self.env.open_db(key=b'kels.', dupsort=True)
        self.pses = self.env.open_db(key=b'pses.', dupsort=True)
        self.ooes = self.env.open_db(key=b'ooes.', dupsort=True)
        self.dels = self.env.open_db(key=b'dels.', dupsort=True)
        self.ldes = self.env.open_db(key=b'ldes.', dupsort=True)


    def putEvt(self, key, val):
        """
        Use dgKey()
        Write serialized event bytes val to key
        Does not overwrite existing val if any
        Returns True If val successfully written Else False
        Return False if key already exists
        """
        return self.putVal(self.evts, key, val)


    def setEvt(self, key, val):
        """
        Use dgKey()
        Write serialized event bytes val to key
        Overwrites existing val if any
        Returns True If val successfully written Else False
        """
        return self.setVal(self.evts, key, val)


    def getEvt(self, key):
        """
        Use dgKey()
        Return event at key
        Returns None if no entry at key
        """
        return self.getVal(self.evts, key)


    def delEvt(self, key):
        """
        Use dgKey()
        Deletes value at key.
        Returns True If key exists in database Else False
        """
        return self.delVal(self.evts, key)


    def putDts(self, key, val):
        """
        Use dgKey()
        Write serialized event datetime stamp val to key
        Does not overwrite existing val if any
        Returns True If val successfully written Else False
        Returns False if key already exists
        """
        return self.putVal(self.dtss, key, val)


    def setDts(self, key, val):
        """
        Use dgKey()
        Write serialized event datetime stamp val to key
        Overwrites existing val if any
        Returns True If val successfully written Else False
        """
        return self.setVal(self.dtss, key, val)


    def getDts(self, key):
        """
        Use dgKey()
        Return datetime stamp at key
        Returns None if no entry at key
        """
        return self.getVal(self.dtss, key)


    def delDts(self, key):
        """
        Use dgKey()
        Deletes value at key.
        Returns True If key exists in database Else False
        """
        return self.delVal(self.dtss, key)


    def getSigs(self, key):
        """
        Use dgKey()
        Return list of signatures at key
        Returns empty list if no entry at key
        Duplicates are retrieved in lexocographic order not insertion order.
        """
        return self.getVals(self.sigs, key)


    def getSigsIter(self, key):
        """
        Use dgKey()
        Return iterator of signatures at key
        Raises StopIteration Error when empty
        Duplicates are retrieved in lexocographic order not insertion order.
        """
        return self.getValsIter(self.sigs, key)


    def putSigs(self, key, vals):
        """
        Use dgKey()
        Write each entry from list of bytes signatures vals to key
        Adds to existing signatures at key if any
        Returns True If no error
        Apparently always returns True (is this how .put works with dupsort=True)
        Duplicates are inserted in lexocographic order not insertion order.
        """
        return self.putVals(self.sigs, key, vals)


    def addSig(self, key, val):
        """
        Use dgKey()
        Add signature val bytes as dup to key in db
        Adds to existing values at key if any
        Returns True if written else False if dup val already exists
        Duplicates are inserted in lexocographic order not insertion order.
        """
        return self.addVal(self.sigs, key, val)


    def cntSigs(self, key):
        """
        Use dgKey()
        Return count of signatures at key
        Returns zero if no entry at key
        """
        return self.cntVals(self.sigs, key)


    def delSigs(self, key, val=b''):
        """
        Use dgKey()
        Deletes all values at key if val = b'' else deletes dup val = val.
        Returns True If key exists in database (or key, val if val not b'') Else False
        """
        return self.delVals(self.sigs, key, val)


    def putRcts(self, key, vals):
        """
        Use dgKey()
        Write each entry from list of bytes receipt couplets vals to key
        Adds to existing receipts at key if any
        Returns True If no error
        Apparently always returns True (is this how .put works with dupsort=True)
        Duplicates are inserted in lexocographic order not insertion order.
        """
        return self.putVals(self.rcts, key, vals)


    def addRct(self, key, val):
        """
        Use dgKey()
        Add receipt couplet val bytes as dup to key in db
        Adds to existing values at key if any
        Returns True if written else False if dup val already exists
        Duplicates are inserted in lexocographic order not insertion order.
        """
        return self.addVal(self.rcts, key, val)


    def getRcts(self, key):
        """
        Use dgKey()
        Return list of receipt couplets at key
        Returns empty list if no entry at key
        Duplicates are retrieved in lexocographic order not insertion order.
        """
        return self.getVals(self.rcts, key)


    def getRctsIter(self, key):
        """
        Use dgKey()
        Return iterator of receipt couplets at key
        Raises StopIteration Error when empty
        Duplicates are retrieved in lexocographic order not insertion order.
        """
        return self.getValsIter(self.rcts, key)


    def cntRcts(self, key):
        """
        Use dgKey()
        Return count of receipt couplets at key
        Returns zero if no entry at key
        """
        return self.cntVals(self.rcts, key)


    def delRcts(self, key, val=b''):
        """
        Use dgKey()
        Deletes all values at key if val = b'' else deletes dup val = val.
        Returns True If key exists in database (or key, val if val not b'') Else False
        """
        return self.delVals(self.rcts, key, val)


    def putUres(self, key, vals):
        """
        Use snKey()
        Write each entry from list of bytes receipt triples vals to key
        Triplet is dig + pre + sig
        Adds to existing receipts at key if any
        Returns True If at least one of vals is added as dup, False otherwise
        Duplicates are inserted in insertion order.
        """
        return self.putIoVals(self.ures, key, vals)


    def addUre(self, key, val):
        """
        Use snKey()
        Add receipt triplet val bytes as dup to key in db
        Triplet is dig + pre + sig
        Adds to existing values at key if any
        Returns True If at least one of vals is added as dup, False otherwise
        Duplicates are inserted in insertion order.
        """
        return self.addIoVal(self.ures, key, val)


    def getUres(self, key):
        """
        Use snKey()
        Return list of receipt triplets at key
        Triplet is dig + pre + sig
        Returns empty list if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoVals(self.ures, key)


    def getUresIter(self, key):
        """
        Use snKey()
        Return iterator of receipt triplets at key
        Triplet is dig + pre + sig
        Raises StopIteration Error when empty
        Duplicates are retrieved in insertion order.
        """
        return self.getIoValsIter(self.ures, key)


    def getUreLast(self, key):
        """
        Use snKey()
        Return last inserted dup partial signed escrowed event triplet val at key
        Triplet is dig + pre + sig
        Returns None if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoValLast(self.ures, key)


    def getUreItemsNext(self, key=b'', skip=True):
        """
        Use snKey()
        Return all dups of partial signed escrowed event triplet items at next
        key after key.
        Item is (key, val) where proem has already been stripped from val
        val is triplet dig + pre + sig
        If key is b'' empty then returns dup items at first key.
        If skip is False and key is not b'' empty then returns dup items at key
        Returns empty list if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoItemsNext(self.ures, key, skip)


    def getUreItemsNextIter(self, key=b'', skip=True):
        """
        Use sgKey()
        Return iterator of partial signed escrowed event triplet items at next
        key after key.
        Items is (key, val) where proem has already been stripped from val
        val is triplet dig + pre + sig
        If key is b'' empty then returns dup items at first key.
        If skip is False and key is not b'' empty then returns dup items at key
        Raises StopIteration Error when empty
        Duplicates are retrieved in insertion order.
        """
        return self.getIoItemsNextIter(self.ures, key, skip)


    def cntUres(self, key):
        """
        Use snKey()
        Return count of receipt triplets at key
        Returns zero if no entry at key
        """
        return self.cntIoVals(self.ures, key)


    def delUres(self, key):
        """
        Use snKey()
        Deletes all values at key in db.
        Returns True If key exists in database Else False
        """
        return self.delIoVals(self.ures, key)


    def delUre(self, key, val):
        """
        Use snKey()
        Deletes dup val at key in db.
        Returns True If dup at  exists in db Else False

        Parameters:
            key is bytes of key within sub db's keyspace
            val is dup val (does not include insertion ordering proem)
        """
        return self.delIoVal(self.ures, key, val)


    def putVrcs(self, key, vals):
        """
        Use dgKey()
        Write each entry from list of bytes receipt quadlets vals to key
        quadlet is spre+ssnu+sdig+sig
        Adds to existing receipts at key if any
        Returns True If no error
        Apparently always returns True (is this how .put works with dupsort=True)
        Duplicates are inserted in lexocographic order not insertion order.
        """
        return self.putVals(self.vrcs, key, vals)


    def addVrc(self, key, val):
        """
        Use dgKey()
        Add receipt quadlet val bytes as dup to key in db
        quadlet is spre+ssnu+sdig+sig
        Adds to existing values at key if any
        Returns True if written else False if dup val already exists
        Duplicates are inserted in lexocographic order not insertion order.
        """
        return self.addVal(self.vrcs, key, val)


    def getVrcs(self, key):
        """
        Use dgKey()
        Return list of receipt quadlet at key
        quadlet is spre+ssnu+sdig+sig
        Returns empty list if no entry at key
        Duplicates are retrieved in lexocographic order not insertion order.
        """
        return self.getVals(self.vrcs, key)


    def getVrcsIter(self, key):
        """
        Use dgKey()
        Return iterator of receipt quadlets at key
        quadlet is spre+ssnu+sdig+sig
        Raises StopIteration Error when empty
        Duplicates are retrieved in lexocographic order not insertion order.
        """
        return self.getValsIter(self.vrcs, key)


    def cntVrcs(self, key):
        """
        Use dgKey()
        Return count of receipt quadlets at key
        Returns zero if no entry at key
        """
        return self.cntVals(self.vrcs, key)


    def delVrcs(self, key, val=b''):
        """
        Use dgKey()
        Deletes all values at key if val = b'' else deletes dup val = val.
        Returns True If key exists in database (or key, val if val not b'') Else False
        """
        return self.delVals(self.vrcs, key, val)


    def putVres(self, key, vals):
        """
        Use snKey()
        Write each entry from list of bytes receipt quinlets vals to key
        Quinlet is edig + spre + ssnu + sdig +sig
        Adds to existing receipts at key if any
        Returns True If at least one of vals is added as dup, False otherwise
        Duplicates are inserted in insertion order.
        """
        return self.putIoVals(self.vres, key, vals)


    def addVre(self, key, val):
        """
        Use snKey()
        Add receipt quinlet val bytes as dup to key in db
        Quinlet is edig + spre + ssnu + sdig +sig
        Adds to existing values at key if any
        Returns True If at least one of vals is added as dup, False otherwise
        Duplicates are inserted in insertion order.
        """
        return self.addIoVal(self.vres, key, val)


    def getVres(self, key):
        """
        Use snKey()
        Return list of receipt quinlets at key
        Quinlet is edig + spre + ssnu + sdig +sig
        Returns empty list if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoVals(self.vres, key)


    def getVresIter(self, key):
        """
        Use snKey()
        Return iterator of receipt quinlets at key
        Quinlet is edig + spre + ssnu + sdig +sig
        Raises StopIteration Error when empty
        Duplicates are retrieved in insertion order.
        """
        return self.getIoValsIter(self.vres, key)


    def getVreLast(self, key):
        """
        Use snKey()
        Return last inserted dup partial signed escrowed event quinlet val at key
        Quinlet is edig + spre + ssnu + sdig +sig
        Returns None if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoValLast(self.vres, key)


    def getVreItemsNext(self, key=b'', skip=True):
        """
        Use snKey()
        Return all dups of partial signed escrowed event quinlet items at next
        key after key.
        Item is (key, val) where proem has already been stripped from val
        val is Quinlet is edig + spre + ssnu + sdig +sig
        If key is b'' empty then returns dup items at first key.
        If skip is False and key is not b'' empty then returns dup items at key
        Returns empty list if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoItemsNext(self.vres, key, skip)


    def getVreItemsNextIter(self, key=b'', skip=True):
        """
        Use sgKey()
        Return iterator of partial signed escrowed event quinlet items at next
        key after key.
        Items is (key, val) where proem has already been stripped from val
        val is Quinlet is edig + spre + ssnu + sdig +sig
        If key is b'' empty then returns dup items at first key.
        If skip is False and key is not b'' empty then returns dup items at key
        Raises StopIteration Error when empty
        Duplicates are retrieved in insertion order.
        """
        return self.getIoItemsNextIter(self.vres, key, skip)


    def cntVres(self, key):
        """
        Use snKey()
        Return count of receipt quinlets at key
        Returns zero if no entry at key
        """
        return self.cntIoVals(self.vres, key)


    def delVres(self, key):
        """
         Use snKey()
        Deletes all values at key in db.
        Returns True If key exists in database Else False
        """
        return self.delIoVals(self.vres, key)


    def delVre(self, key, val):
        """
        Use snKey()
        Deletes dup val at key in db.
        Returns True If dup at  exists in db Else False

        Parameters:
            key is bytes of key within sub db's keyspace
            val is dup val (does not include insertion ordering proem)
        """
        return self.delIoVal(self.vres, key, val)


    def putKes(self, key, vals):
        """
        Use snKey()
        Write each key event dig entry from list of bytes vals to key
        Adds to existing event indexes at key if any
        Returns True If at least one of vals is added as dup, False otherwise
        Duplicates are inserted in insertion order.
        """
        return self.putIoVals(self.kels, key, vals)


    def addKe(self, key, val):
        """
        Use snKey()
        Add key event val bytes as dup to key in db
        Adds to existing event indexes at key if any
        Returns True if written else False if dup val already exists
        Duplicates are inserted in insertion order.
        """
        return self.addIoVal(self.kels, key, val)


    def getKes(self, key):
        """
        Use snKey()
        Return list of key event dig vals at key
        Returns empty list if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoVals(self.kels, key)


    def getKeLast(self, key):
        """
        Use snKey()
        Return last inserted dup key event dig vals at key
        Returns None if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoValLast(self.kels, key)


    def cntKes(self, key):
        """
        Use snKey()
        Return count of dup key event dig val at key
        Returns zero if no entry at key
        """
        return self.cntIoVals(self.kels, key)


    def delKes(self, key):
        """
        Use snKey()
        Deletes all values at key.
        Returns True If key exists in database Else False
        """
        return self.delIoVals(self.kels, key)


    def getKelIter(self, pre):
        """
        Returns iterator of all dup vals in insertion order for all entries
        with same prefix across all sequence numbers without gaps. Stops if
        encounters gap.
        Assumes that key is combination of prefix and sequence number given
        by .snKey().

        Raises StopIteration Error when empty.
        Duplicates are retrieved in insertion order.

        Parameters:
            db is opened named sub db with dupsort=True
            pre is bytes of itdentifier prefix prepended to sn in key
                within sub db's keyspace
        """
        if hasattr(pre, "encode"):
            pre = pre.encode("utf-8")  # convert str to bytes
        return self.getIoValsAllPreIter(self.kels, pre)


    def getKelEstIter(self, pre):
        """
        Returns iterator of last one of dup vals at each key in insertion order
        for all entries with same prefix across all sequence numbers without gaps.
        Stops if encounters gap.
        Assumes that key is combination of prefix and sequence number given
        by .snKey().

        Raises StopIteration Error when empty.
        Duplicates are retrieved in insertion order.

        Parameters:
            db is opened named sub db with dupsort=True
            pre is bytes of itdentifier prefix prepended to sn in key
                within sub db's keyspace
        """
        if hasattr(pre, "encode"):
            pre = pre.encode("utf-8")  # convert str to bytes
        return self.getIoValLastAllPreIter(self.kels, pre)


    def putPses(self, key, vals):
        """
        Use snKey()
        Write each partial signed escrow event entry from list of bytes dig vals to key
        Adds to existing event indexes at key if any
        Returns True If at least one of vals is added as dup, False otherwise
        Duplicates are inserted in insertion order.
        """
        return self.putIoVals(self.pses, key, vals)


    def addPse(self, key, val):
        """
        Use snKey()
        Add Partial signed escrow val bytes as dup to key in db
        Adds to existing event indexes at key if any
        Returns True if written else False if dup val already exists
        Duplicates are inserted in insertion order.
        """
        return self.addIoVal(self.pses, key, val)


    def getPses(self, key):
        """
        Use snKey()
        Return list of partial signed escrowed event dig vals at key
        Returns empty list if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoVals(self.pses, key)


    def getPsesIter(self, key):
        """
        Use sgKey()
        Return iterator of partial signed escrowed event dig vals at key
        Raises StopIteration Error when empty
        Duplicates are retrieved in insertion order.
        """
        return self.getIoValsIter(self.pses, key)


    def getPseLast(self, key):
        """
        Use snKey()
        Return last inserted dup partial signed escrowed event dig val at key
        Returns None if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoValLast(self.pses, key)


    def getPseItemsNext(self, key=b'', skip=True):
        """
        Use snKey()
        Return all dups of partial signed escrowed event dig items at next key after key.
        Item is (key, val) where proem has already been stripped from val
        If key is b'' empty then returns dup items at first key.
        If skip is False and key is not b'' empty then returns dup items at key
        Returns empty list if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoItemsNext(self.pses, key, skip)


    def getPseItemsNextIter(self, key=b'', skip=True):
        """
        Use sgKey()
        Return iterator of partial signed escrowed event dig items at next key after key.
        Items is (key, val) where proem has already been stripped from val
        If key is b'' empty then returns dup items at first key.
        If skip is False and key is not b'' empty then returns dup items at key
        Raises StopIteration Error when empty
        Duplicates are retrieved in insertion order.
        """
        return self.getIoItemsNextIter(self.pses, key, skip)


    def cntPses(self, key):
        """
        Use snKey()
        Return count of dup event dig vals at key
        Returns zero if no entry at key
        """
        return self.cntIoVals(self.pses, key)


    def delPses(self, key):
        """
        Use snKey()
        Deletes all values at key in db.
        Returns True If key  exists in db Else False
        """
        return self.delIoVals(self.pses, key)


    def delPse(self, key, val):
        """
        Use snKey()
        Deletes dup val at key in db.
        Returns True If dup at  exists in db Else False

        Parameters:
            key is bytes of key within sub db's keyspace
            val is dup val (does not include insertion ordering proem)
        """
        return self.delIoVal(self.pses, key, val)


    def putOoes(self, key, vals):
        """
        Use snKey()
        Write each out of order escrow event dig entry from list of bytes vals to key
        Adds to existing event indexes at key if any
        Returns True If at least one of vals is added as dup, False otherwise
        Duplicates are inserted in insertion order.
        """
        return self.putIoVals(self.ooes, key, vals)


    def addOoe(self, key, val):
        """
        Use snKey()
        Add out of order escrow val bytes as dup to key in db
        Adds to existing event indexes at key if any
        Returns True if written else False if dup val already exists
        Duplicates are inserted in insertion order.
        """
        return self.addIoVal(self.ooes, key, val)


    def getOoes(self, key):
        """
        Use snKey()
        Return list of out of order escrow event dig vals at key
        Returns empty list if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoVals(self.ooes, key)


    def getOoeLast(self, key):
        """
        Use snKey()
        Return last inserted dup val of out of order escrow event dig vals at key
        Returns None if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoValLast(self.ooes, key)


    def getOoeItemsNext(self, key=b'', skip=True):
        """
        Use snKey()
        Return all dups of out of order escrowed event dig items at next key after key.
        Item is (key, val) where proem has already been stripped from val
        If key is b'' empty then returns dup items at first key.
        If skip is False and key is not b'' empty then returns dup items at key
        Returns empty list if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoItemsNext(self.ooes, key, skip)


    def getOoeItemsNextIter(self, key=b'', skip=True):
        """
        Use sgKey()
        Return iterator of out of order escrowed event dig items at next key after key.
        Items is (key, val) where proem has already been stripped from val
        If key is b'' empty then returns dup items at first key.
        If skip is False and key is not b'' empty then returns dup items at key
        Raises StopIteration Error when empty
        Duplicates are retrieved in insertion order.
        """
        return self.getIoItemsNextIter(self.ooes, key, skip)


    def cntOoes(self, key):
        """
        Use snKey()
        Return count of dup event dig at key
        Returns zero if no entry at key
        """
        return self.cntIoVals(self.ooes, key)


    def delOoes(self, key):
        """
        Use snKey()
        Deletes all values at key.
        Returns True If key exists in database Else False
        """
        return self.delIoVals(self.ooes, key)


    def delOoe(self, key, val):
        """
        Use snKey()
        Deletes dup val at key in db.
        Returns True If dup at  exists in db Else False

        Parameters:
            db is opened named sub db with dupsort=True
            key is bytes of key within sub db's keyspace
            val is dup val (does not include insertion ordering proem)
        """
        return self.delIoVal(self.ooes, key, val)


    def putDes(self, key, vals):
        """
        Use snKey()
        Write each duplicitous event entry dig from list of bytes vals to key
        Adds to existing event indexes at key if any
        Returns True If at least one of vals is added as dup, False otherwise
        Duplicates are inserted in insertion order.
        """
        return self.putIoVals(self.dels, key, vals)


    def addDe(self, key, val):
        """
        Use snKey()
        Add duplicate event index val bytes as dup to key in db
        Adds to existing event indexes at key if any
        Returns True if written else False if dup val already exists
        Duplicates are inserted in insertion order.
        """
        return self.addIoVal(self.dels, key, val)


    def getDes(self, key):
        """
        Use snKey()
        Return list of duplicitous event dig vals at key
        Returns empty list if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoVals(self.dels, key)


    def getDeLast(self, key):
        """
        Use snKey()
        Return last inserted dup value of duplicitous event dig vals at key
        Returns None if no entry at key

        Duplicates are retrieved in insertion order.
        """
        return self.getIoValLast(self.dels, key)


    def cntDes(self, key):
        """
        Use snKey()
        Return count of dup event dig vals at key
        Returns zero if no entry at key
        """
        return self.cntIoVals(self.dels, key)


    def delDes(self, key):
        """
        Use snKey()
        Deletes all values at key.
        Returns True If key exists in database Else False
        """
        return self.delIoVals(self.dels, key)


    def getDelIter(self, pre):
        """
        Returns iterator of all dup vals  in insertion order for any entries
        with same prefix across all sequence numbers including gaps.
        Assumes that key is combination of prefix and sequence number given
        by .snKey().

        Raises StopIteration Error when empty.
        Duplicates are retrieved in insertion order.

        Parameters:
            db is opened named sub db with dupsort=True
            pre is bytes of itdentifier prefix prepended to sn in key
                within sub db's keyspace
        """
        if hasattr(pre, "encode"):
            pre = pre.encode("utf-8")  # convert str to bytes
        return self.getIoValsAnyPreIter(self.dels, pre)


    def putLdes(self, key, vals):
        """
        Use snKey()
        Write each likely duplicitous event entry dig from list of bytes vals to key
        Adds to existing event indexes at key if any
        Returns True If at least one of vals is added as dup, False otherwise
        Duplicates are inserted in insertion order.
        """
        return self.putIoVals(self.ldes, key, vals)


    def addLde(self, key, val):
        """
        Use snKey()
        Add likely duplicitous escrow val bytes as dup to key in db
        Adds to existing event indexes at key if any
        Returns True if written else False if dup val already exists
        Duplicates are inserted in insertion order.
        """
        return self.addIoVal(self.ldes, key, val)


    def getLdes(self, key):
        """
        Use snKey()
        Return list of likely duplicitous event dig vals at key
        Returns empty list if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoVals(self.ldes, key)


    def getLdeLast(self, key):
        """
        Use snKey()
        Return last inserted dup val of likely duplicitous event dig vals at key
        Returns None if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoValLast(self.ldes, key)


    def getLdeItemsNext(self, key=b'', skip=True):
        """
        Use snKey()
        Return all dups of likely duplicitous escrowed event dig items at next key after key.
        Item is (key, val) where proem has already been stripped from val
        If key is b'' empty then returns dup items at first key.
        If skip is False and key is not b'' empty then returns dup items at key
        Returns empty list if no entry at key
        Duplicates are retrieved in insertion order.
        """
        return self.getIoItemsNext(self.ldes, key, skip)


    def getLdeItemsNextIter(self, key=b'', skip=True):
        """
        Use sgKey()
        Return iterator of likely duplicitous escrowed event dig items at next key after key.
        Items is (key, val) where proem has already been stripped from val
        If key is b'' empty then returns dup items at first key.
        If skip is False and key is not b'' empty then returns dup items at key
        Raises StopIteration Error when empty
        Duplicates are retrieved in insertion order.
        """
        return self.getIoItemsNextIter(self.ldes, key, skip)


    def cntLdes(self, key):
        """
        Use snKey()
        Return count of dup event dig at key
        Returns zero if no entry at key
        """
        return self.cntIoVals(self.ldes, key)


    def delLdes(self, key):
        """
        Use snKey()
        Deletes all values at key.
        Returns True If key exists in database Else False
        """
        return self.delIoVals(self.ldes, key)


    def delLde(self, key, val):
        """
        Use snKey()
        Deletes dup val at key in db.
        Returns True If dup at  exists in db Else False

        Parameters:
            db is opened named sub db with dupsort=True
            key is bytes of key within sub db's keyspace
            val is dup val (does not include insertion ordering proem)
        """
        return self.delIoVal(self.ldes, key, val)



class BaserDoer(doing.Doer):
    """
    Basic Baser Doer ( LMDB Database )

    Inherited Attributes:
        .done is Boolean completion state:
            True means completed
            Otherwise incomplete. Incompletion maybe due to close or abort.

    Attributes:
        .baser is Baser or LMDBer subclass

    Inherited Properties:
        .tyme is float ._tymist.tyme, relative cycle or artificial time
        .tock is float, desired time in seconds between runs or until next run,
                 non negative, zero means run asap

    Properties:

    Methods:
        .wind  injects ._tymist dependency
        .__call__ makes instance callable
            Appears as generator function that returns generator
        .do is generator method that returns generator
        .enter is enter context action method
        .recur is recur context action method or generator method
        .exit is exit context method
        .close is close context method
        .abort is abort context method

    Hidden:
       ._tymist is Tymist instance reference
       ._tock is hidden attribute for .tock property
    """

    def __init__(self, baser, **kwa):
        """
        Inherited Parameters:
           tymist is Tymist instance
           tock is float seconds initial value of .tock

        Parameters:
           baser is Baser instance
        """
        super(BaserDoer, self).__init__(**kwa)
        self.baser = baser


    def enter(self):
        """"""
        self.baser.reopen()


    def exit(self):
        """"""
        self.baser.close()
