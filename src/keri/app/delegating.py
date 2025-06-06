# -*- encoding: utf-8 -*-
"""
KERI
keri.app.delegating module

module for enveloping and forwarding KERI message
"""

from hio.base import doing

from . import agenting, forwarding
from .habbing import GroupHab
from .. import help
from .. import kering
from ..core import coring, serdering
from ..db import dbing
from ..peer import exchanging

logger = help.ogler.getLogger()


class Anchorer(doing.DoDoer):
    """Anchorer subclass of DoDoer
    Sends messages to Delegator of an identifier and wait for the anchoring event to
    be processed to ensure the inception or rotation event has been approved by the delegator.

    Removes all Doers and exits as Done once the event has been anchored.

    """

    def __init__(self, hby, proxy=None, auths=None, **kwa):
        """
        For the current event, gather the current set of witnesses, send the event,
        gather all receipts and send them to all other witnesses

        Parameters:
            hab (Hab): Habitat of the identifier to populate witnesses
            msg (bytes): is the message to send to all witnesses.
                 Defaults to sending the latest KEL event if msg is None
            scheme (str): Scheme to favor if available

        """
        self.hby = hby
        self.postman = forwarding.Poster(hby=hby)
        self.witq = agenting.WitnessInquisitor(hby=hby)
        self.witDoer = agenting.Receiptor(hby=self.hby)
        self.publishers = dict()
        self.proxy = proxy
        self.auths = auths

        super(Anchorer, self).__init__(doers=[self.witq, self.witDoer, self.postman, doing.doify(self.escrowDo)], **kwa)

    def delegation(self, pre, sn=None, proxy=None, auths=None):
        if pre not in self.hby.habs:
            raise kering.ValidationError(f"{pre} is not a valid local AID for delegation")

        if proxy is not None:
            self.proxy = proxy

        self.publishers[pre] = agenting.WitnessPublisher(hby=self.hby)
        # load the hab of the delegated identifier to anchor
        hab = self.hby.habs[pre]
        delpre = hab.kever.delpre  # get the delegator identifier
        if delpre not in hab.kevers:
            raise kering.ValidationError(f"delegator {delpre} not found, unable to process delegation")

        sn = sn if sn is not None else hab.kever.sner.num
        self.auths = auths if auths is not None else self.auths

        # load the event and signatures
        evt = hab.makeOwnEvent(sn=sn)

        # Send exn message for notification purposes
        srdr = serdering.SerderKERI(raw=evt)
        self.witDoer.msgs.append(dict(pre=pre, sn=srdr.sn, auths=self.auths))
        self.hby.db.dpwe.pin(keys=(srdr.pre, srdr.said), val=srdr)

    def complete(self, prefixer, seqner, saider=None):
        """ Check for completed delegation protocol for the specific event

        Parameters:
            prefixer (Prefixer): qb64 identifier prefix of event to check
            seqner (Seqner): sequence number of event to check
            saider (Saider): optional digest of event to verify

        Returns:

        """
        csaider = self.hby.db.cdel.get(keys=(prefixer.qb64, seqner.qb64))
        if not csaider:
            return False
        else:
            if saider and (csaider.qb64 != saider.qb64):
                raise kering.ValidationError(f"invalid delegation protocol escrowed event {csaider.qb64}-{saider.qb64}")

        return True

    def escrowDo(self, tymth, tock=1.0, **kwa):
        """ Process escrows of group multisig identifiers waiting to be compeleted.

        Steps involve:
           1. Sending local event with sig to other participants
           2. Waiting for signature threshold to be met.
           3. If elected and delegated identifier, send complete event to delegator
           4. If delegated, wait for delegator's anchored seal
           5. If elected, send event to witnesses and collect receipts.
           6. Otherwise, wait for fully receipted event

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value.  Default to 1.0 to slow down processing

        """
        # enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        while True:
            self.processEscrows()
            yield 0.5

    def processEscrows(self):
        self.processPartialWitnessEscrow()
        self.processUnanchoredEscrow()
        self.processWitnessPublication()

    def processUnanchoredEscrow(self):
        """
        Process escrow of partially signed multisig group KEL events.  Message
        processing will send this local controllers signature to all other participants
        then this escrow waits for signatures from all other participants

        """
        for (pre, said), serder in self.hby.db.dune.getItemIter():  # group partial witness escrow
            kever = self.hby.kevers[pre]
            dkever = self.hby.kevers[kever.delpre]

            seal = dict(i=serder.pre, s=serder.snh, d=serder.said)
            if dserder := self.hby.db.fetchLastSealingEventByEventSeal(dkever.prefixer.qb64, seal=seal):
                seqner = coring.Seqner(sn=dserder.sn)
                couple = seqner.qb64b + dserder.saidb
                dgkey = dbing.dgKey(kever.prefixer.qb64b, kever.serder.saidb)
                self.hby.db.setAes(dgkey, couple)  # authorizer event seal (delegator/issuer)

                # Move to escrow waiting for witness receipts
                logger.info(f"Delegation approval received, {serder.pre} confirmed, publishing to my witnesses")
                self.publishDelegator(pre)
                self.hby.db.dpub.put(keys=(pre, said), val=serder)
                self.hby.db.dune.rem(keys=(pre, said))

    def processPartialWitnessEscrow(self):
        """
        Process escrow of delegated events that do not have a full compliment of receipts
        from witnesses yet.  When receipting is complete, remove from escrow and cue up a message
        that the event is complete.

        """
        for (pre, said), serder in self.hby.db.dpwe.getItemIter():  # group partial witness escrow
            kever = self.hby.kevers[pre]
            dgkey = dbing.dgKey(pre, serder.said)
            seqner = coring.Seqner(sn=serder.sn)

            # Load all the witness receipts we have so far
            wigs = self.hby.db.getWigs(dgkey)
            if len(wigs) == len(kever.wits):  # We have all of them, this event is finished
                if len(kever.wits) > 0:
                    witnessed = False
                    for cue in self.witDoer.cues:
                        if cue["pre"] == serder.pre and cue["sn"] == seqner.sn:
                            witnessed = True
                    if not witnessed:
                        continue
                logger.info(f"Witness receipts complete, waiting for delegation approval.")
                if pre not in self.hby.habs:
                    continue

                hab = self.hby.habs[pre]
                delpre = hab.kever.delpre  # get the delegator identifier
                dkever = hab.kevers[delpre]  # and the delegator's kever
                smids = []

                if isinstance(hab, GroupHab):
                    phab = hab.mhab
                    smids = hab.smids
                elif self.proxy is not None:
                    phab = self.proxy
                else:
                    raise kering.ValidationError("no proxy to send messages for delegation")

                evt = hab.db.cloneEvtMsg(pre=serder.pre, fn=0, dig=serder.said)
                srdr = serdering.SerderKERI(raw=evt)
                exn, atc = delegateRequestExn(phab, delpre=delpre, evt=bytes(evt), aids=smids)

                logger.info(
                    "Sending delegation request exn for %s from %s to delegator %s", srdr.ilk, phab.pre, delpre)
                logger.debug("Delegation request=\n%s\n", exn.pretty())
                self.postman.send(hab=phab, dest=hab.kever.delpre, topic="delegate", serder=exn, attachment=atc)

                del evt[:srdr.size]
                logger.info("Sending delegation event %s from %s to delegator %s", srdr.ilk, phab.pre, delpre)
                logger.debug("Delegated inception=\n%s\n", srdr.pretty())
                self.postman.send(hab=phab, dest=delpre, topic="delegate", serder=srdr, attachment=evt)

                seal = dict(i=srdr.pre, s=srdr.snh, d=srdr.said)
                self.witq.query(hab=phab, pre=dkever.prefixer.qb64, anchor=seal)

                self.hby.db.dpwe.rem(keys=(pre, said))
                self.hby.db.dune.pin(keys=(srdr.pre, srdr.said), val=srdr)

    def processWitnessPublication(self):
        """
        Process escrow of partially signed multisig group KEL events.  Message
        processing will send this local controllers signature to all other participants
        then this escrow waits for signatures from all other participants

        """
        for (pre, said), serder in self.hby.db.dpub.getItemIter():  # group partial witness escrow
            if pre not in self.publishers:
                continue

            publisher = self.publishers[pre]

            if not publisher.idle:
                continue

            self.remove([publisher])
            del self.publishers[pre]

            self.hby.db.dpub.rem(keys=(pre, said))
            self.hby.db.cdel.put(keys=(pre, coring.Seqner(sn=serder.sn).qb64), val=coring.Saider(qb64=serder.said))

    def publishDelegator(self, pre):
        if pre not in self.publishers:
            return

        publisher = self.publishers[pre]
        hab = self.hby.habs[pre]
        self.extend([publisher])
        for msg in hab.db.cloneDelegation(hab.kever):
            publisher.msgs.append(dict(pre=hab.pre, msg=bytes(msg)))


def loadHandlers(hby, exc, notifier):
    """ Load handlers for the peer-to-peer delegation protocols

    Parameters:
        hby (Habery): Database and keystore for environment
        exc (Exchanger): Peer-to-peer message router
        notifier (Notifier): Outbound notifications

    """
    delreq = DelegateRequestHandler(hby=hby, notifier=notifier)
    exc.addHandler(delreq)


class DelegateRequestHandler:
    """
    Handler for multisig group inception notification EXN messages

    """
    resource = "/delegate/request"

    def __init__(self, hby, notifier):
        """

        Parameters:
            hby (Habery) database environment for this handler
            notifier (str) notifier for converting delegate request exn messages to controller notifications

        """
        self.hby = hby
        self.notifier = notifier

    def handle(self, serder, attachments=None):
        """  Do route specific processsing of delegation request messages

        Parameters:
            serder (Serder): Serder of the exn delegation request message
            attachments (list): list of tuples of pather, CESR SAD path attachments to the exn event

        """

        src = serder.pre
        pay = serder.ked['a']
        embeds = serder.ked['e']

        delpre = pay["delpre"]
        if delpre not in self.hby.habs:
            logger.error(f"invalid delegate request message, no local delpre for evt=: {pay}")
            return

        data = dict(
            src=src,
            r='/delegate/request',
            delpre=delpre,
            ked=embeds["evt"]
        )
        if "aids" in pay:
            data["aids"] = pay["aids"]

        self.notifier.add(attrs=data)


def delegateRequestExn(hab, delpre, evt, aids=None):
    """

    Parameters:
        hab (Hab): database environment of sender
        delpre (str): qb64 AID of delegator
        evt (bytes): serialized and signed event requiring delegation approval
        aids (list): list of multisig AIDs participating

    Returns:

    """
    data = dict(
        delpre=delpre,
    )

    embeds = dict(
        evt=evt
    )

    if aids is not None:
        data["aids"] = aids

    # Create `exn` peer to peer message to notify other participants UI
    exn, _ = exchanging.exchange(route=DelegateRequestHandler.resource, modifiers=dict(),
                                 payload=data, sender=hab.pre, embeds=embeds)
    ims = hab.endorse(serder=exn, last=False, pipelined=False)
    del ims[:exn.size]

    return exn, ims
