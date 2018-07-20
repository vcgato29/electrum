import threading

from .util import PrintError, bh2u, bfh, NoDynamicFeeEstimates
from .lnutil import (extract_ctn_from_tx, derive_privkey,
                     get_per_commitment_secret_from_seed, derive_pubkey,
                     make_commitment_output_to_remote_address,
                     RevocationStore, UnableToDeriveSecret)
from . import lnutil
from .bitcoin import redeem_script_to_address, TYPE_ADDRESS
from . import transaction
from .transaction import Transaction
from . import ecc
from . import wallet

TX_MINED_STATUS_DEEP, TX_MINED_STATUS_SHALLOW, TX_MINED_STATUS_MEMPOOL, TX_MINED_STATUS_FREE = range(0, 4)

from .storage import WalletStorage
from .address_synchronizer import AddressSynchronizer


class LNWatcher(PrintError):
    # TODO if verifier gets an incorrect merkle proof, that tx will never verify!!
    # similarly, what if server ignores request for merkle proof?
    # maybe we should disconnect from server in these cases

    def __init__(self, network):
        self.network = network
        self.watched_channels = {}
        storage = WalletStorage('blah')
        self.synchronizer = AddressSynchronizer(storage)
        self.synchronizer.start_threads(network)
        self.lock = threading.Lock()
        self.watched_addresses = set()
        self.network.register_callback(self.on_network_update, ['updated'])
        self.sweepstore = defaultdict({})


    def watch_channel(self, chan, sweep_address, callback):
        funding_address = chan.get_funding_address()
        outpoint = chan.funding_outpoint
        channel_info = {
            'sweep_address': sweep_address,
            'local_pubkey': chan.local_config.payment_basepoint.pubkey,
            'remote_pubkey': chan.remote_config.payment_basepoint.pubkey,
            'latest_local_ctn': chan.local_state.ctn,
            'latest_remote_ctn': chan.remote_state.ctn
        }
        self.watch_address(funding_address)
        self.watched_channels[funding_address] = channel_info
        #self.watched_channels[outpoint] = chan, callback

    def on_network_update(self, event, *args):
        if not self.synchronizer.synchronizer.is_up_to_date():
            return
        for funding_address, chan_info in self.watched_channels.items():
            self.check_onchain_situation(outpoint)

    def watch_address(self, addr):
        with self.lock:
            self.watched_addresses.add(addr)
            self.synchronizer.synchronizer.add(addr)

    def check_onchain_situation(self, funding_outpoint):
        ctx_candidate_txid = self.synchronizer.spent_outpoints[funding_outpoint.txid].get(funding_outpoint.output_index)
        if ctx_candidate_txid is None:
            return
        ctx_candidate = self.synchronizer.transactions.get(ctx_candidate_txid)
        if ctx_candidate is None:
            return
        #self.print_error("funding outpoint {} is spent by {}"
        #                 .format(funding_outpoint, ctx_candidate_txid))
        for i, txin in enumerate(ctx_candidate.inputs()):
            if txin['type'] == 'coinbase': continue
            prevout_hash = txin['prevout_hash']
            prevout_n = txin['prevout_n']
            if prevout_hash == funding_outpoint.txid and prevout_n == funding_outpoint.output_index:
                break
        else:
            raise Exception('{} is supposed to be spent by {}, but none of the inputs spend it'
                            .format(funding_outpoint, ctx_candidate_txid))
        height, conf, timestamp = self.synchronizer.get_tx_height(ctx_candidate_txid)
        if conf == 0:
            return
        keep_watching_this = self.inspect_ctx_candidate(ctx_candidate, i)
        if not keep_watching_this:
            self.stop_and_delete()

    # TODO batch sweeps
    # TODO sweep HTLC outputs
    def inspect_ctx_candidate(self, ctx, txin_idx: int):
        """Returns True iff found any not-deeply-spent outputs that we could
        potentially sweep at some point."""
        keep_watching_this = False
        chan = self.chan
        sweep_address = channel_info['sweep_address']
        ctn = extract_ctn_from_tx(ctx, txin_idx,local_pubkey, remote_pubkey)
        self.print_error("ctx {} has ctn {}. latest local ctn is {}, latest remote ctn is {}"
                         .format(ctx.txid(), ctn, latest_local_ctn, latest_remote_ctn))
        # see if it is a normal unilateral close by them
        if ctn == latest_remote_ctn:
            # note that we might also get here if this is our ctx and the ctn just happens to match
            their_cur_pcp = chan.remote_state.current_per_commitment_point
            if their_cur_pcp is not None:
                keep_watching_this |= self.find_and_sweep_their_ctx_to_remote(ctn, ctx, their_cur_pcp, sweep_address)
        # see if we have a revoked secret for this ctn ("breach")
        try:
            per_commitment_secret = chan.remote_state.revocation_store.retrieve_secret(
                RevocationStore.START_INDEX - ctn)
        except UnableToDeriveSecret:
            self.print_error("revocation store does not have secret for ctx {}".format(ctx.txid()))
        else:
            # note that we might also get here if this is our ctx and we just happen to have
            # the secret for the symmetric ctn
            their_pcp = ecc.ECPrivkey(per_commitment_secret).get_public_key_bytes(compressed=True)
            keep_watching_this |= self.find_and_sweep_their_ctx_to_remote(ctn, ctx, their_pcp, sweep_address)
            keep_watching_this |= self.find_and_sweep_their_ctx_to_local(ctn, ctx, per_commitment_secret, sweep_address)

        # see if it's our ctx
        our_per_commitment_secret = get_per_commitment_secret_from_seed(
            chan.local_state.per_commitment_secret_seed, RevocationStore.START_INDEX - ctn)
        our_per_commitment_point = ecc.ECPrivkey(our_per_commitment_secret).get_public_key_bytes(compressed=True)
        keep_watching_this |= self.find_and_sweep_our_ctx_to_local(ctn, ctx, our_per_commitment_point, sweep_address)
        return keep_watching_this

    def add_ctx_to_sweepstore(self, chan, our_ctx, their_ctx):
        sweep_tx = create_sweeptx_their_ctx_to_remote(self.network, sweep_address, their_ctx, output_idx, our_payment_privkey)
        self.sweepstore[ctn]['their_ctx_to_remote'] = sweep_tx


    def get_tx_mined_status(self, txid):
        if not txid:
            return TX_MINED_STATUS_FREE
        height, conf, timestamp = self.synchronizer.get_tx_height(txid)
        if conf > 100:
            return TX_MINED_STATUS_DEEP
        elif conf > 0:
            return TX_MINED_STATUS_SHALLOW
        elif height in (wallet.TX_HEIGHT_UNCONFIRMED, wallet.TX_HEIGHT_UNCONF_PARENT):
            return TX_MINED_STATUS_MEMPOOL
        elif height == wallet.TX_HEIGHT_LOCAL:
            return TX_MINED_STATUS_FREE
        elif height > 0 and conf == 0:
            # unverified but claimed to be mined
            return TX_MINED_STATUS_MEMPOOL
        else:
            raise NotImplementedError()

    def find_and_sweep_their_ctx_to_remote(self, ctn, ctx, their_pcp: bytes, sweep_address):
        """Returns True iff found a not-deeply-spent output that we could
        potentially sweep at some point."""
        payment_bp_privkey = ecc.ECPrivkey(self.chan.local_config.payment_basepoint.privkey)
        our_payment_privkey = derive_privkey(payment_bp_privkey.secret_scalar, their_pcp)
        our_payment_privkey = ecc.ECPrivkey.from_secret_scalar(our_payment_privkey)
        our_payment_pubkey = our_payment_privkey.get_public_key_bytes(compressed=True)
        to_remote_address = make_commitment_output_to_remote_address(our_payment_pubkey)
        for output_idx, (type_, addr, val) in enumerate(ctx.outputs()):
            if type_ == TYPE_ADDRESS and addr == to_remote_address:
                self.print_error("found to_remote output paying to us: ctx {}:{}".
                                 format(ctx.txid(), output_idx))
                #self.print_error("ctx {} is normal unilateral close by them".format(ctx.txid()))
                break
        else:
            return False
        if to_remote_address not in self.watched_addresses:
            self.watch_address(to_remote_address)
            return True
        spending_txid = self.synchronizer.spent_outpoints[ctx.txid()].get(output_idx)
        stx_mined_status = self.get_tx_mined_status(spending_txid)
        if stx_mined_status == TX_MINED_STATUS_DEEP:
            return False
        elif stx_mined_status in (TX_MINED_STATUS_SHALLOW, TX_MINED_STATUS_MEMPOOL):
            return True

        sweep_tx = self.sweepstore[ctn]['their_ctx_to_remote']
        self.network.broadcast_transaction(sweep_tx,
                                           lambda res: self.print_tx_broadcast_result('sweep_their_ctx_to_remote', res))
        return True

        


    def find_and_sweep_their_ctx_to_local(self, ctx, per_commitment_secret: bytes, sweep_address):
        """Returns True iff found a not-deeply-spent output that we could
        potentially sweep at some point."""
        per_commitment_point = ecc.ECPrivkey(per_commitment_secret).get_public_key_bytes(compressed=True)
        revocation_privkey = lnutil.derive_blinded_privkey(self.chan.local_config.revocation_basepoint.privkey,
                                                           per_commitment_secret)
        revocation_pubkey = ecc.ECPrivkey(revocation_privkey).get_public_key_bytes(compressed=True)
        to_self_delay = self.chan.local_config.to_self_delay
        delayed_pubkey = derive_pubkey(self.chan.remote_config.delayed_basepoint.pubkey,
                                       per_commitment_point)
        witness_script = bh2u(lnutil.make_commitment_output_to_local_witness_script(
            revocation_pubkey, to_self_delay, delayed_pubkey))
        to_local_address = redeem_script_to_address('p2wsh', witness_script)
        for output_idx, (type_, addr, val) in enumerate(ctx.outputs()):
            if type_ == TYPE_ADDRESS and addr == to_local_address:
                self.print_error("found to_local output paying to them: ctx {}:{}".
                                 format(ctx.txid(), output_idx))
                break
        else:
            self.print_error('could not find to_local output in their ctx {}'.format(ctx.txid()))
            return False
        if to_local_address not in self.watched_addresses:
            self.watch_address(to_local_address)
            return True
        spending_txid = self.synchronizer.spent_outpoints[ctx.txid()].get(output_idx)
        stx_mined_status = self.get_tx_mined_status(spending_txid)
        if stx_mined_status == TX_MINED_STATUS_DEEP:
            return False
        elif stx_mined_status in (TX_MINED_STATUS_SHALLOW, TX_MINED_STATUS_MEMPOOL):
            return True
        sweep_tx = create_sweeptx_ctx_to_local(self.network, sweep_address, ctx, output_idx,
                                               witness_script, revocation_privkey, True)
        self.network.broadcast_transaction(sweep_tx,
                                           lambda res: self.print_tx_broadcast_result('sweep_their_ctx_to_local', res))
        return True

    def find_and_sweep_our_ctx_to_local(self, ctx, our_pcp: bytes, sweep_address):
        """Returns True iff found a not-deeply-spent output that we could
        potentially sweep at some point."""
        delayed_bp_privkey = ecc.ECPrivkey(self.chan.local_config.delayed_basepoint.privkey)
        our_localdelayed_privkey = derive_privkey(delayed_bp_privkey.secret_scalar, our_pcp)
        our_localdelayed_privkey = ecc.ECPrivkey.from_secret_scalar(our_localdelayed_privkey)
        our_localdelayed_pubkey = our_localdelayed_privkey.get_public_key_bytes(compressed=True)
        revocation_pubkey = lnutil.derive_blinded_pubkey(self.chan.remote_config.revocation_basepoint.pubkey,
                                                         our_pcp)
        to_self_delay = self.chan.remote_config.to_self_delay
        witness_script = bh2u(lnutil.make_commitment_output_to_local_witness_script(
            revocation_pubkey, to_self_delay, our_localdelayed_pubkey))
        to_local_address = redeem_script_to_address('p2wsh', witness_script)
        for output_idx, (type_, addr, val) in enumerate(ctx.outputs()):
            if type_ == TYPE_ADDRESS and addr == to_local_address:
                self.print_error("found to_local output paying to us (CSV-locked): ctx {}:{}".
                                 format(ctx.txid(), output_idx))
                break
        else:
            self.print_error('could not find to_local output in our ctx {}'.format(ctx.txid()))
            return False
        if to_local_address not in self.watched_addresses:
            self.watch_address(to_local_address)
            return True
        spending_txid = self.synchronizer.spent_outpoints[ctx.txid()].get(output_idx)
        stx_mined_status = self.get_tx_mined_status(spending_txid)
        if stx_mined_status == TX_MINED_STATUS_DEEP:
            return False
        elif stx_mined_status in (TX_MINED_STATUS_SHALLOW, TX_MINED_STATUS_MEMPOOL):
            return True
        # check timelock
        ctx_num_conf = self.synchronizer.get_tx_height(ctx.txid())[1]
        if to_self_delay > ctx_num_conf:
            self.print_error('waiting for CSV ({} < {}) for ctx {}'.format(ctx_num_conf, to_self_delay, ctx.txid()))
            return True
        sweep_tx = create_sweeptx_ctx_to_local(self.network, sweep_address, ctx, output_idx,
                                               witness_script, our_localdelayed_privkey.get_secret_bytes(),
                                               False, to_self_delay)
        sweep_tx = self.get_sweep_ctx_to_local()
        self.network.broadcast_transaction(sweep_tx,
                                           lambda res: self.print_tx_broadcast_result('sweep_our_ctx_to_local', res))
        return True

    def print_tx_broadcast_result(self, name, res):
        error = res.get('error')
        if error:
            self.print_error('{} broadcast failed: {}'.format(name, error))
        else:
            self.print_error('{} broadcast succeeded'.format(name))


def create_sweeptx_their_ctx_to_remote(network, address, ctx, output_idx: int, our_payment_privkey: ecc.ECPrivkey):
    our_payment_pubkey = our_payment_privkey.get_public_key_hex(compressed=True)
    val = ctx.outputs()[output_idx][2]
    sweep_inputs = [{
        'type': 'p2wpkh',
        'x_pubkeys': [our_payment_pubkey],
        'num_sig': 1,
        'prevout_n': output_idx,
        'prevout_hash': ctx.txid(),
        'value': val,
        'coinbase': False,
        'signatures': [None],
    }]
    tx_size_bytes = 110  # approx size of p2wpkh->p2wpkh
    try:
        fee = network.config.estimate_fee(tx_size_bytes)
    except NoDynamicFeeEstimates:
        fee_per_kb = network.config.fee_per_kb(dyn=False)
        fee = network.config.estimate_fee_for_feerate(fee_per_kb, tx_size_bytes)
    sweep_outputs = [(TYPE_ADDRESS, address, val-fee)]
    locktime = network.get_local_height()
    sweep_tx = Transaction.from_io(sweep_inputs, sweep_outputs, locktime=locktime)
    sweep_tx.set_rbf(True)
    sweep_tx.sign({our_payment_pubkey: (our_payment_privkey.get_secret_bytes(), True)})
    if not sweep_tx.is_complete():
        raise Exception('channel close sweep tx is not complete')
    return sweep_tx


def create_sweeptx_ctx_to_local(network, address, ctx, output_idx: int, witness_script: str,
                                privkey: bytes, is_revocation: bool, to_self_delay: int=None):
    """Create a txn that sweeps the 'to_local' output of a commitment
    transaction into our wallet.

    privkey: either revocation_privkey or localdelayed_privkey
    is_revocation: tells us which ^
    """
    val = ctx.outputs()[output_idx][2]
    sweep_inputs = [{
        'scriptSig': '',
        'type': 'p2wsh',
        'signatures': [],
        'num_sig': 0,
        'prevout_n': output_idx,
        'prevout_hash': ctx.txid(),
        'value': val,
        'coinbase': False,
        'preimage_script': witness_script,
    }]
    if to_self_delay is not None:
        sweep_inputs[0]['sequence'] = to_self_delay
    tx_size_bytes = 121  # approx size of to_local -> p2wpkh
    try:
        fee = network.config.estimate_fee(tx_size_bytes)
    except NoDynamicFeeEstimates:
        fee_per_kb = network.config.fee_per_kb(dyn=False)
        fee = network.config.estimate_fee_for_feerate(fee_per_kb, tx_size_bytes)
    sweep_outputs = [(TYPE_ADDRESS, address, val - fee)]
    locktime = network.get_local_height()
    sweep_tx = Transaction.from_io(sweep_inputs, sweep_outputs, locktime=locktime, version=2)
    sig = sweep_tx.sign_txin(0, privkey)
    witness = transaction.construct_witness([sig, int(is_revocation), witness_script])
    sweep_tx.inputs()[0]['witness'] = witness
    return sweep_tx
