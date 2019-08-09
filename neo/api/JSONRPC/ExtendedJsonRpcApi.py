from neo.Core.Blockchain import Blockchain
from neo.api.JSONRPC.JsonRpcApi import JsonRpcApi, JsonRpcError
from neo.Implementations.Wallets.peewee.UserWallet import UserWallet
from neocore.UInt256 import UInt256
import datetime
from neo.Wallets.utils import to_aes_key
import os
from shutil import copy
from threading import Timer


class ExtendedJsonRpcApi(JsonRpcApi):
    """
    Extended JSON-RPC API Methods
    """

    def __init__(self, port, rpc_user=None, rpc_password=None, wallet=None,
                 wallet_backup=None):
        self.start_height = Blockchain.Default().Height
        self.start_dt = datetime.datetime.utcnow()
        self.port = port
        self.rpc_user = rpc_user
        self.rpc_password = rpc_password
        self.wallet_backup = wallet_backup
        self.timer = None
        super(ExtendedJsonRpcApi, self).__init__(port, wallet)

    def json_rpc_method_handler(self, method, params):

        if method == "getnodestate":
            height = Blockchain.Default().Height
            headers = Blockchain.Default().HeaderHeight
            diff = height - self.start_height
            now = datetime.datetime.utcnow()
            difftime = now - self.start_dt
            mins = difftime / datetime.timedelta(minutes=1)
            secs = mins * 60
            bpm = 0
            tps = 0

            if diff > 0 and mins > 0:
                bpm = diff / mins
                tps = Blockchain.Default().TXProcessed / secs

            return {
                'current_block': height,
                'header_height': headers,
                'block_cache_length': Blockchain.Default().BlockCacheCount,
                'blocks_since_program_start': diff,
                'time_elapsed': mins,
                'blocks_per_min': bpm,
                'tps': tps
            }

        elif method == "gettxhistory":
            if self.wallet:
                res = []
                for tx in self.wallet.GetTransactions():
                    json = tx.ToJson()
                    tx_id = UInt256.ParseString(json['txid'])
                    txx, height = Blockchain.Default().GetTransaction(tx_id)
                    header = Blockchain.Default().GetHeaderByHeight(height)
                    block_index = header.Index
                    json['block_index'] = block_index
                    block_timestamp = header.Timestamp
                    json['blocktime'] = block_timestamp
                    res.append(json)
                return res
            else:
                raise JsonRpcError(-400, "Access denied.")

        elif method == "walletpassphrase":
            if self.wallet is None:
                return "You wallet path is not specified."
            if not os.path.exists(self.wallet):
                return "Wallet path does not exist."
            try:
                passwd = to_aes_key(params[0])
                try:
                    wallet_open_time = params[1]
                    if not type(wallet_open_time) == int:
                        return "Wallet timeout duration should be " \
                               "provided as integer."
                except IndexError:
                    wallet_open_time = 60
                self.wallet = UserWallet.Open(self.wallet, passwd)
                try:
                    if not self.timer.is_alive():
                        self.set_timer(wallet_open_time, self.wallet_close)
                except AttributeError:
                    self.set_timer(wallet_open_time, self.wallet_close)

                return "Wallet is opened. In {} seconds will be closed." \
                    .format(wallet_open_time)
            except Exception as e:
                return "Wallet wasn't opened. Error: {}".format(e)

        elif method == "walletlock":
            self.wallet_close()
            return "Wallet is closed."

        elif method == "backupwallet":
            backup_path = None
            if params[0] is not None:
                backup_path = params[0]
            elif self.wallet_backup is not None:
                backup_path = self.wallet_backup
            if backup_path is None:
                return "Error. Wallet backup path is not specified."
            if self.wallet is None:
                return "Error. Wallet path is not known."
            try:
                copy(self.wallet, self.wallet_backup)
                return "Your wallet was successfully backed up."
            except Exception as e:
                return "Wallet backup wasn't initiated. Error: {}".format(e)

        elif method == "walletcreate":
            try:
                path = params[0]
                passwd = params[1]
            except IndexError:
                return "Please provide two parameters: " \
                       "wallet path and password."

            if os.path.exists(path):
                return "Wallet file already exists. " \
                       "You don't want to override it."

            password_key = to_aes_key(passwd)

            try:
                UserWallet.Create(path=path, password=password_key)
            except Exception as e:
                error_msg = "Error. {}".format(e)
                if os.path.isfile(path):
                    try:
                        os.remove(path)
                    except Exception as e:
                        error_msg = error_msg + \
                                    "Could not remove {}: {}".format(path, e)
                return error_msg

            return 'Wallet was created.'

        return super(ExtendedJsonRpcApi, self).\
            json_rpc_method_handler(method, params)

    def set_timer(self, time, func):
        self.timer = Timer(time, func)
        self.timer.start()

    def wallet_close(self):
        if self.wallet:
            try:
                self.wallet.Close()
                self.timer.cancel()
            except AttributeError:
                pass
            self.wallet = None
        return

