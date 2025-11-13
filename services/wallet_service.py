from models import Wallet, Transaction, User
from web3 import Web3
from eth_account import Account
from decimal import Decimal
import os
from dotenv import load_dotenv
import logging
from datetime import datetime, timezone
from typing import Optional, Dict
from web3.exceptions import BlockNotFound
import time

load_dotenv()
logger = logging.getLogger(__name__)


class WalletService:
    def __init__(self, db=None, socketio=None):
        self.db = db
        self.socketio = socketio

        self.network = "sepolia"
        self.rpc_url = os.getenv("SEPOLIA_RPC_URL")

        if not self.rpc_url or "YOUR_INFURA_KEY" in self.rpc_url:
            raise ValueError(
                "SEPOLIA_RPC_URL not configured! Get a free key from https://infura.io"
            )

        self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))

        if not self.w3.is_connected():
            logger.error(f"Failed to connect to {self.network} via {self.rpc_url}")
            raise ConnectionError(f"Cannot connect to Sepolia RPC")

        logger.info(f"Connected to Sepolia testnet. Chain ID: {self.w3.eth.chain_id}")

        self.exchange_private_key = os.getenv("EXCHANGE_PRIVATE_KEY")
        if not self.exchange_private_key:
            raise ValueError("EXCHANGE_PRIVATE_KEY not set in environment")

        self.exchange_account = Account.from_key(self.exchange_private_key)
        self.exchange_address = self.exchange_account.address

        logger.info(f"Exchange hot wallet: {self.exchange_address}")

        self.min_confirmations = int(os.getenv("MIN_CONFIRMATIONS", "3"))

        self.min_eth_balance = Decimal("0.0001")
        self.min_gas_reserve = Decimal("0.01")

    def create_user_deposit_address(self, user_id: int) -> Dict[str, str]:
        from models import EthereumWallet

        try:
            existing_wallet = EthereumWallet.query.filter_by(
                user_id=user_id,
                is_active=True
            ).first()

            if existing_wallet:
                logger.info(f"User {user_id} already has deposit address: {existing_wallet.address}")
                return {
                    "address": existing_wallet.address,
                    "network": self.network,
                    "created_at": existing_wallet.created_at.isoformat(),
                    "instructions": (
                        f"Send ETH to this address on Sepolia testnet. "
                        f"Get testnet ETH from https://sepoliafaucet.com"
                    )
                }

            account = Account.create()
            encrypted_key = EthereumWallet.encrypt_private_key(account.key.hex())

            new_wallet = EthereumWallet(
                user_id=user_id,
                address=account.address,
                encrypted_private_key=encrypted_key,
                network=self.network,
                is_active=True,
                created_at=datetime.now(timezone.utc)
            )

            self.db.session.add(new_wallet)
            self.db.session.commit()

            logger.info(f"Created new deposit address for user {user_id}: {account.address}")

            return {
                "address": account.address,
                "network": self.network,
                "created_at": new_wallet.created_at.isoformat(),
                "instructions": (
                    f"Send ETH to this address on Sepolia testnet. "
                    f"Minimum deposit: {self.min_eth_balance} ETH. "
                    f"Get testnet ETH from https://sepoliafaucet.com"
                )
            }

        except Exception as e:
            self.db.session.rollback()
            logger.error(f"Error creating deposit address for user {user_id}: {e}")
            raise

    def check_deposit(self, user_id: int, address: str) -> Optional[Dict]:
        try:
            address = Web3.to_checksum_address(address)

            balance_wei = self.w3.eth.get_balance(address)
            balance_eth = self.w3.from_wei(balance_wei, 'ether')

            if balance_eth == 0:
                return None

            logger.info(f"Found {balance_eth} ETH at {address} for user {user_id}")

            if Decimal(str(balance_eth)) < self.min_eth_balance:
                logger.info(f"Balance below minimum deposit of {self.min_eth_balance} ETH")
                return None

            latest_block = self.w3.eth.block_number

            deposit_tx = self._find_deposit_transaction(address, latest_block)

            if not deposit_tx:
                logger.warning(f"Could not find deposit transaction for {address}")
                return None

            confirmations = latest_block - deposit_tx['blockNumber']

            if confirmations < self.min_confirmations:
                logger.info(
                    f"Deposit has {confirmations}/{self.min_confirmations} confirmations"
                )
                return {
                    "status": "pending",
                    "confirmations": confirmations,
                    "required_confirmations": self.min_confirmations,
                    "amount": float(balance_eth),
                    "tx_hash": deposit_tx['hash'].hex()
                }

            existing_tx = Transaction.query.filter_by(
                blockchain_tx_hash=deposit_tx['hash'].hex(),
                user_id=user_id
            ).first()

            if existing_tx:
                logger.info(f"Deposit already processed: {deposit_tx['hash'].hex()}")
                return None

            return self._process_confirmed_deposit(
                user_id=user_id,
                user_address=address,
                amount_eth=Decimal(str(balance_eth)),
                tx_hash=deposit_tx['hash'].hex(),
                block_number=deposit_tx['blockNumber']
            )

        except Exception as e:
            logger.error(f"Error checking deposit for {address}: {e}")
            return None

    def _find_deposit_transaction(self, address: str, latest_block: int) -> Optional[Dict]:
        try:
            search_blocks = min(1000, latest_block)

            for block_num in range(latest_block, latest_block - search_blocks, -1):
                try:
                    block = self.w3.eth.get_block(block_num, full_transactions=True)

                    for tx in block['transactions']:
                        if tx['to'] and tx['to'].lower() == address.lower():
                            if tx['value'] > 0:
                                return tx

                except BlockNotFound:
                    continue

            return None

        except Exception as e:
            logger.error(f"Error finding deposit transaction: {e}")
            return None

    def _process_confirmed_deposit(
            self,
            user_id: int,
            user_address: str,
            amount_eth: Decimal,
            tx_hash: str,
            block_number: int
    ) -> Dict:
        try:
            self.db.session.begin_nested()

            user_wallet = Wallet.query.filter_by(
                user_id=user_id,
                currency='ETH'
            ).with_for_update().first()

            if not user_wallet:
                user_wallet = Wallet(
                    user_id=user_id,
                    currency='ETH',
                    balance=Decimal('0'),
                    locked_balance=Decimal('0'),
                    is_active=True
                )
                self.db.session.add(user_wallet)

            user_wallet.balance += amount_eth
            user_wallet.total_deposited += amount_eth
            user_wallet.last_updated = datetime.now(timezone.utc)

            transaction = Transaction(
                user_id=user_id,
                tx_type='deposit',
                currency='ETH',
                amount=amount_eth,
                fee=Decimal('0'),
                blockchain='ethereum',
                from_address=user_address,
                to_address=self.exchange_address,
                blockchain_tx_hash=tx_hash,
                confirmations=self.min_confirmations,
                required_confirmations=self.min_confirmations,
                status='completed',
                created_at=datetime.now(timezone.utc),
                completed_at=datetime.now(timezone.utc)
            )
            self.db.session.add(transaction)

            self.db.session.commit()

            logger.info(
                f"Credited {amount_eth} ETH to user {user_id}. "
                f"New balance: {user_wallet.balance} ETH"
            )

            try:
                sweep_result = self._sweep_deposit_to_exchange(
                    user_address=user_address,
                    amount_wei=self.w3.to_wei(amount_eth, 'ether')
                )

                if sweep_result:
                    logger.info(
                        f"Swept {amount_eth} ETH from {user_address} to exchange wallet. "
                        f"TX: {sweep_result['tx_hash']}"
                    )

            except Exception as sweep_error:
                logger.error(f"Sweep failed (non-critical): {sweep_error}")

            if self.socketio:
                self.socketio.emit('balance_update', {
                    'user_id': user_id,
                    'currency': 'ETH',
                    'balance': float(user_wallet.balance),
                    'type': 'deposit',
                    'amount': float(amount_eth)
                }, room=f'user_{user_id}')

            return {
                "status": "completed",
                "amount": float(amount_eth),
                "currency": "ETH",
                "tx_hash": tx_hash,
                "new_balance": float(user_wallet.balance),
                "transaction_id": transaction.id
            }

        except Exception as e:
            self.db.session.rollback()
            logger.error(f"Error processing deposit: {e}")
            raise

    def _sweep_deposit_to_exchange(
            self,
            user_address: str,
            amount_wei: int
    ) -> Optional[Dict]:
        from models import EthereumWallet

        try:
            eth_wallet = EthereumWallet.query.filter_by(
                address=user_address,
                is_active=True
            ).first()

            if not eth_wallet:
                raise ValueError(f"No wallet found for address {user_address}")

            user_private_key = eth_wallet.decrypt_private_key()
            user_account = Account.from_key(user_private_key)

            gas_price = self.w3.eth.gas_price
            gas_limit = 21000
            gas_cost = gas_price * gas_limit

            send_amount = amount_wei - gas_cost

            if send_amount <= 0:
                logger.warning(
                    f"Cannot sweep {user_address}: insufficient balance for gas"
                )
                return None

            nonce = self.w3.eth.get_transaction_count(user_address)

            tx = {
                'nonce': nonce,
                'to': self.exchange_address,
                'value': send_amount,
                'gas': gas_limit,
                'gasPrice': gas_price,
                'chainId': self.w3.eth.chain_id
            }

            signed_tx = user_account.sign_transaction(tx)
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.raw_transaction)

            logger.info(
                f"Sweep transaction sent: {tx_hash.hex()}. "
                f"Moving {self.w3.from_wei(send_amount, 'ether')} ETH"
            )

            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

            return {
                "tx_hash": tx_hash.hex(),
                "amount_wei": send_amount,
                "amount_eth": float(self.w3.from_wei(send_amount, 'ether')),
                "gas_used": receipt['gasUsed'],
                "status": receipt['status']
            }

        except Exception as e:
            logger.error(f"Sweep failed: {e}")
            return None

    def process_withdrawal(
            self,
            user_id: int,
            to_address: str,
            amount_eth: Decimal,
            require_2fa: bool = True
    ) -> Dict:
        from models import Wallet, Transaction, User

        try:
            to_address = Web3.to_checksum_address(to_address)

            user = User.query.get(user_id)
            if not user:
                raise ValueError("User not found")

            if user.kyc_status != 'approved':
                raise ValueError("KYC verification required for withdrawals")

            if require_2fa and user.two_factor_enabled:
                pass

            self.db.session.begin_nested()

            user_wallet = Wallet.query.filter_by(
                user_id=user_id,
                currency='ETH'
            ).with_for_update().first()

            if not user_wallet:
                raise ValueError("ETH wallet not found")

            fee = max(amount_eth * Decimal('0.001'), Decimal('0.001'))
            total_amount = amount_eth + fee

            if user_wallet.available_balance < total_amount:
                raise ValueError(
                    f"Insufficient balance. Available: {user_wallet.available_balance} ETH, "
                    f"Required: {total_amount} ETH (including {fee} ETH fee)"
                )

            exchange_balance_wei = self.w3.eth.get_balance(self.exchange_address)
            exchange_balance_eth = Decimal(str(self.w3.from_wei(exchange_balance_wei, 'ether')))

            if exchange_balance_eth < (amount_eth + self.min_gas_reserve):
                raise ValueError(
                    "Exchange hot wallet has insufficient funds. Please contact support."
                )

            user_wallet.balance -= total_amount
            user_wallet.total_withdrawn += amount_eth
            user_wallet.last_updated = datetime.now(timezone.utc)

            transaction = Transaction(
                user_id=user_id,
                tx_type='withdrawal',
                currency='ETH',
                amount=amount_eth,
                fee=fee,
                blockchain='ethereum',
                from_address=self.exchange_address,
                to_address=to_address,
                status='processing',
                created_at=datetime.now(timezone.utc)
            )
            self.db.session.add(transaction)

            self._add_platform_fee(fee, 'ETH', 'withdrawal_fee')

            self.db.session.commit()

            logger.info(
                f"Processing withdrawal: {amount_eth} ETH from user {user_id} "
                f"to {to_address}"
            )

            try:
                tx_result = self._send_eth_transaction(
                    to_address=to_address,
                    amount_wei=self.w3.to_wei(amount_eth, 'ether')
                )

                transaction.blockchain_tx_hash = tx_result['tx_hash']
                transaction.status = 'completed'
                transaction.completed_at = datetime.now(timezone.utc)
                self.db.session.commit()

                logger.info(f"Withdrawal completed. TX: {tx_result['tx_hash']}")

                if self.socketio:
                    self.socketio.emit('balance_update', {
                        'user_id': user_id,
                        'currency': 'ETH',
                        'balance': float(user_wallet.balance),
                        'type': 'withdrawal',
                        'amount': -float(amount_eth)
                    }, room=f'user_{user_id}')

                return {
                    "success": True,
                    "tx_hash": tx_result['tx_hash'],
                    "amount": float(amount_eth),
                    "fee": float(fee),
                    "to_address": to_address,
                    "status": "completed",
                    "transaction_id": transaction.id,
                    "explorer_url": f"https://sepolia.etherscan.io/tx/{tx_result['tx_hash']}"
                }

            except Exception as tx_error:
                self.db.session.begin_nested()

                user_wallet.balance += total_amount
                transaction.status = 'failed'
                transaction.notes = f"Blockchain transaction failed: {str(tx_error)}"

                self.db.session.commit()

                logger.error(f"Withdrawal blockchain tx failed: {tx_error}")

                raise ValueError(f"Withdrawal failed: {str(tx_error)}")

        except Exception as e:
            self.db.session.rollback()
            logger.error(f"Withdrawal error: {e}")
            raise

    def _send_eth_transaction(self, to_address: str, amount_wei: int) -> Dict:
        try:
            nonce = self.w3.eth.get_transaction_count(self.exchange_address)

            gas_price = self.w3.eth.gas_price
            gas_limit = 21000

            tx = {
                'nonce': nonce,
                'to': to_address,
                'value': amount_wei,
                'gas': gas_limit,
                'gasPrice': gas_price,
                'chainId': self.w3.eth.chain_id
            }

            signed_tx = self.exchange_account.sign_transaction(tx)

            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.raw_transaction)

            logger.info(f"Sent TX: {tx_hash.hex()}")

            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

            if receipt['status'] != 1:
                raise ValueError("Transaction failed on blockchain")

            return {
                "tx_hash": tx_hash.hex(),
                "amount_wei": amount_wei,
                "amount_eth": float(self.w3.from_wei(amount_wei, 'ether')),
                "gas_used": receipt['gasUsed'],
                "block_number": receipt['blockNumber']
            }

        except Exception as e:
            logger.error(f"Failed to send ETH transaction: {e}")
            raise

    def internal_transfer(
            self,
            from_user_id: int,
            to_user_email: str,
            amount: Decimal,
            currency: str = 'ETH',
            memo: Optional[str] = None
    ) -> Dict:
        try:
            amount = Decimal(str(amount))

            if amount <= 0:
                raise ValueError("Amount must be positive")

            self.db.session.begin_nested()

            to_user = User.query.filter_by(email=to_user_email).first()
            if not to_user:
                raise ValueError(f"User not found: {to_user_email}")

            if to_user.id == from_user_id:
                raise ValueError("Cannot transfer to yourself")

            from_wallet = Wallet.query.filter_by(
                user_id=from_user_id,
                currency=currency
            ).with_for_update().first()

            if not from_wallet:
                raise ValueError(f"You don't have a {currency} wallet")

            if from_wallet.available_balance < amount:
                raise ValueError(
                    f"Insufficient balance. Available: {from_wallet.available_balance} {currency}"
                )

            to_wallet = Wallet.query.filter_by(
                user_id=to_user.id,
                currency=currency
            ).with_for_update().first()

            if not to_wallet:
                to_wallet = Wallet(
                    user_id=to_user.id,
                    currency=currency,
                    balance=Decimal('0'),
                    locked_balance=Decimal('0'),
                    is_active=True
                )
                self.db.session.add(to_wallet)

            from_wallet.balance -= amount
            from_wallet.last_updated = datetime.now(timezone.utc)

            to_wallet.balance += amount
            to_wallet.last_updated = datetime.now(timezone.utc)

            transfer_id = f"INT-{int(time.time())}-{from_user_id}-{to_user.id}"

            sender_tx = Transaction(
                user_id=from_user_id,
                tx_type='internal_transfer_out',
                currency=currency,
                amount=amount,
                fee=Decimal('0'),
                to_address=to_user_email,
                reference_id=transfer_id,
                notes=memo,
                status='completed',
                created_at=datetime.now(timezone.utc),
                completed_at=datetime.now(timezone.utc)
            )
            self.db.session.add(sender_tx)

            recipient_tx = Transaction(
                user_id=to_user.id,
                tx_type='internal_transfer_in',
                currency=currency,
                amount=amount,
                fee=Decimal('0'),
                from_address=User.query.get(from_user_id).email,
                reference_id=transfer_id,
                notes=memo,
                status='completed',
                created_at=datetime.now(timezone.utc),
                completed_at=datetime.now(timezone.utc)
            )
            self.db.session.add(recipient_tx)

            self.db.session.commit()

            logger.info(
                f"Internal transfer: {amount} {currency} from user {from_user_id} "
                f"to {to_user_email} (user {to_user.id})"
            )

            if self.socketio:
                self.socketio.emit('balance_update', {
                    'user_id': from_user_id,
                    'currency': currency,
                    'balance': float(from_wallet.balance),
                    'type': 'transfer_out',
                    'amount': -float(amount)
                }, room=f'user_{from_user_id}')

                self.socketio.emit('balance_update', {
                    'user_id': to_user.id,
                    'currency': currency,
                    'balance': float(to_wallet.balance),
                    'type': 'transfer_in',
                    'amount': float(amount)
                }, room=f'user_{to_user.id}')

            return {
                "success": True,
                "transfer_id": transfer_id,
                "amount": float(amount),
                "currency": currency,
                "from_user": from_user_id,
                "to_user": to_user.email,
                "memo": memo,
                "sender_balance": float(from_wallet.balance),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }

        except Exception as e:
            self.db.session.rollback()
            logger.error(f"Internal transfer error: {e}")
            raise

    def _add_platform_fee(self, amount: Decimal, currency: str, fee_type: str):
        from models import PlatformWallet

        platform_wallet = PlatformWallet.query.filter_by(currency=currency).first()

        if not platform_wallet:
            platform_wallet = PlatformWallet(
                currency=currency,
                balance=Decimal('0')
            )
            self.db.session.add(platform_wallet)

        platform_wallet.add_revenue(amount, fee_type)

    def create_user_wallet(self) -> Dict[str, str]:
        account = Account.create()
        return {
            "address": account.address,
            "private_key": account.key.hex(),
            "network": self.network,
            "created_at": datetime.now(timezone.utc).isoformat()
        }


    def get_balance(self, address: str, token: str = "ETH") -> Decimal:
        try:
            address = Web3.to_checksum_address(address)

            if token == "ETH":
                balance_wei = self.w3.eth.get_balance(address)
                return Decimal(str(self.w3.from_wei(balance_wei, "ether")))

        except Exception as e:
            logger.error(f"Error getting balance: {e}")
            return Decimal(0)


wallet_service = None

def init_wallet_service(db, socketio):
    global wallet_service
    wallet_service = WalletService(db=db, socketio=socketio)
    return wallet_service
