#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2014 Thomas Voegtlin
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import traceback
import ssl
import asyncio
from aiorpcx import ClientSession
from threading import Lock
import hashlib
import concurrent.futures

# from .bitcoin import Hash, hash_encode
from .transaction import Transaction
from .util import ThreadJob, bh2u, PrintError
from .bitcoin import address_to_scripthash

class SynchronizerJob(ThreadJob):
    def __init__(self, wallet):
        self.wallet = wallet
        self.synchronizer = Synchronizer(wallet)

    def run(self):
       if self.synchronizer.future.done():
           try:
               self.synchronizer.future.result()
           except:
               traceback.print_exc()
               async def stop():
                   asyncio.get_event_loop().stop()
               try:
                   asyncio.run_coroutine_threadsafe(stop(), self.wallet.network.asyncio_loop).result(1)
               except concurrent.futures.TimeoutError:
                   pass
               #self.wallet.network.remove_jobs(self)

class NotificationSession(ClientSession):

    def __init__(self, subscription_replies, scripthash_to_address, *args, **kwargs):
        super(NotificationSession, self).__init__(*args, **kwargs)
        self.q = subscription_replies
        self.scripthash_to_address = scripthash_to_address

    def notification_handler(self, method):
        if method != "blockchain.scripthash.subscribe":
            return None
        def put_in_queue(*args):
            self.q.put_nowait((self.scripthash_to_address[args[0]],) + args[1:] + ("notification",))
        return put_in_queue

class Synchronizer(PrintError):
    '''The synchronizer keeps the wallet up-to-date with its set of
    addresses and their transactions.  It subscribes over the network
    to wallet addresses, gets the wallet to generate new addresses
    when necessary, requests the transaction history of any addresses
    we don't have the full history of, and requests binary transaction
    data of any transactions the wallet doesn't have.
    '''
    def __init__(self, wallet):
        self.wallet = wallet
        self.requested_histories = {}
        self.requested_tx = {}
        self.requested_addrs = set()
        self.scripthash_to_address = {}
        self.future = asyncio.run_coroutine_threadsafe(self.main(), wallet.network.asyncio_loop)

    def is_up_to_date(self):
        return (not self.requested_tx and not self.requested_histories
                and not self.requested_addrs)

    async def subscribe_to_addresses(self, addresses):
        self.print_error("subscribing to", len(addresses), "addresses")

        b = self.session.new_batch()
        for address in addresses:
            h = address_to_scripthash(address)
            self.scripthash_to_address[h] = address
            b.add_request('blockchain.scripthash.subscribe', [h])

        self.session.send_batch(b)

        await b

        return zip(addresses, b)

    def get_status(self, h):
        if not h:
            return None
        status = ''
        for tx_hash, height in h:
            status += tx_hash + ':%d:' % height
        return bh2u(hashlib.sha256(status.encode('ascii')).digest())

    async def on_address_status(self, params, result):
        addr = params[0]
        history = self.wallet.history.get(addr, [])
        if self.get_status(history) != result:
            # note that at this point 'result' can be None;
            # if we had a history for addr but now the server is telling us
            # there is no history
            if addr not in self.requested_histories:
                self.requested_histories[addr] = result

                # request_address_history
                sch = address_to_scripthash(addr)
                req = self.session.send_request("blockchain.scripthash.get_history", [sch])
                await req

                await self.on_address_history([addr], req.result())
        # remove addr from list only after it is added to requested_histories
        if addr in self.requested_addrs:  # Notifications won't be in
            self.requested_addrs.remove(addr)

    async def on_address_history(self, params, result):
        addr = params[0]
        server_status = self.requested_histories[addr]
        self.print_error("receiving history", addr, len(result))
        hashes = set(map(lambda item: item['tx_hash'], result))
        hist = list(map(lambda item: (item['tx_hash'], item['height']), result))
        # tx_fees
        tx_fees = [(item['tx_hash'], item.get('fee')) for item in result]
        tx_fees = dict(filter(lambda x:x[1] is not None, tx_fees))
        # Check that txids are unique
        if len(hashes) != len(result):
            self.print_error("error: server history has non-unique txids: %s"% addr)
        # Check that the status corresponds to what was announced
        elif self.get_status(hist) != server_status:
            self.print_error("error: status mismatch: %s" % addr)
        else:
            # Store received history
            self.wallet.receive_history_callback(addr, hist, tx_fees)
            # Request transactions we don't have
            # "hist" is a list of [tx_hash, tx_height] lists
            transaction_hashes = []
            for tx_hash, tx_height in hist:
                if tx_hash in self.requested_tx:
                    continue
                if tx_hash in self.wallet.transactions:
                    continue
                transaction_hashes.append(tx_hash)
                self.requested_tx[tx_hash] = tx_height

            if transaction_hashes != []:
                await self.get_transactions(transaction_hashes)
        # Remove request; this allows up_to_date to be True
        self.requested_histories.pop(addr)

    def on_tx_response(self, params, result):
        tx_hash = params[0]
        tx = Transaction(result)
        try:
            tx.deserialize()
        except Exception:
            self.print_msg("cannot deserialize transaction, skipping", tx_hash)
            return
        if tx_hash != tx.txid():
            self.print_error("received tx does not match expected txid ({} != {})"
                             .format(tx_hash, tx.txid()))
            return
        tx_height = self.requested_tx.pop(tx_hash)
        self.wallet.receive_tx_callback(tx_hash, tx, tx_height)
        self.print_error("received tx %s height: %d bytes: %d" %
                         (tx_hash, tx_height, len(tx.raw)))
        # callbacks
        self.wallet.network.trigger_callback('new_transaction', tx)
        if not self.requested_tx:
            self.wallet.network.trigger_callback('updated')

    async def request_missing_txs(self, hist):
        # "hist" is a list of [tx_hash, tx_height] lists
        transaction_hashes = []
        for tx_hash, tx_height in hist:
            if tx_hash in self.requested_tx:
                continue
            if tx_hash in self.wallet.transactions:
                continue
            transaction_hashes.append(tx_hash)
            self.requested_tx[tx_hash] = tx_height

        if transaction_hashes != []: await self.get_transactions(transaction_hashes)

    async def get_transactions(self, hashes):
        b = self.session.new_batch()
        for h in hashes:
            b.add_request('blockchain.transaction.get', [h])

        self.session.send_batch(b)

        await b

        for h, rep in zip(hashes, b):
            self.on_tx_response([h], rep.result())

    async def synchronize_and_subscribe(self, subscription_replies, new_addresses=None):
        if new_addresses is None:
            new_addresses = []
            self.add = new_addresses.append
            self.wallet.synchronize()
            del self.add
        if len(new_addresses) > 0:
            res = await self.subscribe_to_addresses(new_addresses)
            for adr, fut in res:
                subscription_replies.put_nowait((adr, fut.result(), "direct response"))

    async def check_update(self):
        was_up_to_date = False
        while True:
            await asyncio.sleep(1)
            up2date = self.is_up_to_date()
            if up2date != was_up_to_date:
                self.wallet.set_up_to_date(up2date)
                self.wallet.network.trigger_callback('updated')
                was_up_to_date = up2date

    async def main(self):
        subscription_replies = asyncio.Queue()

        task = asyncio.get_event_loop().create_task(self.check_update())

        try:
            conn = self.wallet.network.default_server
            host, port, protocol = conn.split(':')
            assert protocol == 's'
            sslc = ssl.SSLContext(ssl.PROTOCOL_TLS)
            async with NotificationSession(subscription_replies, self.scripthash_to_address, host, int(port), ssl=sslc) as session:
                self.session = session

                self.wallet.synchronizer = self
                self.add = lambda x: None
                self.wallet.synchronize()
                del self.add
                adrs = self.wallet.get_addresses()
                await self.synchronize_and_subscribe(subscription_replies, adrs)

                while True:
                    args = await subscription_replies.get()
                    await self.on_address_status([args[0]], args[1])
                    if subscription_replies.qsize() == 0:
                        await self.synchronize_and_subscribe(subscription_replies)
        finally:
            task.cancel()
