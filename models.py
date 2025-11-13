import dotenv
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from sqlalchemy import text
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from sqlalchemy.dialects.postgresql import UUID
from cryptography.fernet import Fernet
import uuid
import os
import base64
from sqlalchemy.orm import Query
dotenv.load_dotenv()
db = SQLAlchemy()

# Encryption key for wallet private keys (load from environment)
WALLET_KMS_KEY = os.environ.get('WALLET_KMS_KEY')

if not WALLET_KMS_KEY:
    # NEVER generate a new key - this will make existing wallets unrecoverable
    raise ValueError(
        "WALLET_KMS_KEY environment variable is required! "
        "Generate one with: python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'"
    )

if isinstance(WALLET_KMS_KEY, str):
    WALLET_ENCRYPTION_KEY = WALLET_KMS_KEY.encode()
else:
    WALLET_ENCRYPTION_KEY = WALLET_KMS_KEY

cipher_suite = Fernet(WALLET_ENCRYPTION_KEY)


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(UUID(as_uuid=True), unique=True, default=uuid.uuid4, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)  # ADD THIS
    password_hash = db.Column(db.String(256), nullable=False)

    # Profile
    full_name = db.Column(db.String(100))
    country = db.Column(db.String(2))
    phone = db.Column(db.String(20))

    # Status
    is_active = db.Column(db.Boolean, default=True, index=True)
    is_verified = db.Column(db.Boolean, default=False, index=True)
    is_admin = db.Column(db.Boolean, default=False)

    # VIP Status
    vip_tier = db.Column(db.String(10), default='VIP0')
    trading_volume_30d = db.Column(db.Numeric(20, 8), default=0)

    # Security
    two_factor_enabled = db.Column(db.Boolean, default=False)
    two_factor_secret = db.Column(db.String(32))
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)

    # KYC
    kyc_status = db.Column(db.String(20), default='unverified', index=True)
    kyc_submitted_at = db.Column(db.DateTime)
    kyc_verified_at = db.Column(db.DateTime)

    # API Access
    api_key = db.Column(db.String(64), unique=True, index=True)
    api_secret = db.Column(db.String(128))
    api_enabled = db.Column(db.Boolean, default=False)
    api_rate_limit = db.Column(db.Integer, default=1000)  # requests per hour

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc), index=True)
    updated_at = db.Column(db.DateTime, default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime)
    last_activity = db.Column(db.DateTime, default=datetime.now(timezone.utc))

    # Relationships
    wallets = db.relationship('Wallet', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    orders = db.relationship('Order', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    transactions = db.relationship('Transaction', backref='user', lazy='dynamic', cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_api_keys(self):
        """Generate new API key and secret"""
        import secrets
        self.api_key = secrets.token_urlsafe(32)
        self.api_secret = secrets.token_urlsafe(64)
        return self.api_key, self.api_secret

    def is_account_locked(self):
        """Check if account is locked due to failed login attempts"""
        if self.locked_until and self.locked_until > datetime.now(timezone.utc):
            return True
        return False

    def update_trading_volume(self, amount):
        """Update 30-day trading volume and VIP tier"""
        self.trading_volume_30d = (self.trading_volume_30d or Decimal('0')) + amount
        
        # Update VIP tier based on volume
        if self.trading_volume_30d >= Decimal('100000'):
            self.vip_tier = 'VIP3'
        elif self.trading_volume_30d >= Decimal('50000'):
            self.vip_tier = 'VIP2'
        elif self.trading_volume_30d >= Decimal('10000'):
            self.vip_tier = 'VIP1'
        else:
            self.vip_tier = 'VIP0'

    def to_dict(self):
        return {
            'id': self.id,
            'uuid': str(self.uuid),
            'email': self.email,
            'is_verified': self.is_verified,
            'kyc_status': self.kyc_status,
            'vip_tier': self.vip_tier,
            'trading_volume_30d': float(self.trading_volume_30d or 0),
            'created_at': self.created_at.isoformat()
        }


class Wallet(db.Model):
    __tablename__ = 'wallets'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    currency = db.Column(db.String(10), nullable=False, index=True)

    # Balances (use Decimal for precision)
    balance = db.Column(db.Numeric(20, 8), default=0, nullable=False)
    locked_balance = db.Column(db.Numeric(20, 8), default=0, nullable=False)
    
    # Additional tracking columns (FIXED: Added missing columns)
    total_deposited = db.Column(db.Numeric(20, 8), default=0, nullable=False)
    total_withdrawn = db.Column(db.Numeric(20, 8), default=0, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    # Deposit address (for blockchain assets)
    deposit_address = db.Column(db.String(100), unique=True, index=True)
    
    # Wallet type
    wallet_type = db.Column(db.String(10), default='hot')  # hot, cold

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    last_updated = db.Column(db.DateTime, default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc), index=True)

    __table_args__ = (
        db.UniqueConstraint('user_id', 'currency', name='unique_user_currency'),
        db.Index('idx_wallet_user_currency', 'user_id', 'currency'),
        db.Index('idx_wallet_currency_balance', 'currency', 'balance'),
    )

    @property
    def available_balance(self):
        return max(Decimal('0'), self.balance - self.locked_balance)

    def lock_funds(self, amount: Decimal) -> bool:
        """Lock funds for orders with pessimistic locking"""
        amount = Decimal(str(amount))

        # Re-query with lock
        wallet = db.session.query(Wallet).filter_by(
            id=self.id
        ).with_for_update().first()

        if wallet.available_balance >= amount:
            wallet.locked_balance += amount
            wallet.last_updated = datetime.now(timezone.utc)
            db.session.flush()  # Ensure write before commit
            return True
        return False

    def unlock_funds(self, amount):
        """Unlock funds from cancelled orders"""
        amount = Decimal(str(amount))
        self.locked_balance = max(Decimal('0'), self.locked_balance - amount)
        self.last_updated = datetime.now(timezone.utc)

    def to_dict(self):
        return {
            'currency': self.currency,
            'balance': float(self.balance),
            'locked_balance': float(self.locked_balance),
            'available_balance': float(self.available_balance),
            'deposit_address': self.deposit_address,
            'last_updated': self.last_updated.isoformat()
        }


class EthereumWallet(db.Model):
    """Secure Ethereum wallet with encrypted private keys"""
    __tablename__ = 'ethereum_wallets'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Ethereum address
    address = db.Column(db.String(42), unique=True, nullable=False, index=True)
    # CRITICAL: Store encrypted private key, never plain text
    encrypted_private_key = db.Column(db.Text, nullable=False)
    
    # Wallet network and status
    network = db.Column(db.String(20), default='ethereum')
    is_active = db.Column(db.Boolean, default=True)
    last_sync = db.Column(db.DateTime)
    
    # Expiration for temporary deposit addresses
    expires_at = db.Column(db.DateTime)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))

    user = db.relationship('User', backref=db.backref('eth_wallets', lazy='dynamic'))

    @staticmethod
    def encrypt_private_key(private_key):
        """Encrypt private key for secure storage"""
        return cipher_suite.encrypt(private_key.encode()).decode()

    def decrypt_private_key(self):
        """Decrypt private key for use (only in memory!)"""
        return cipher_suite.decrypt(self.encrypted_private_key.encode()).decode()

    def to_dict(self):
        return {
            'address': self.address,
            'network': self.network,
            'is_active': self.is_active,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'created_at': self.created_at.isoformat()
        }


class Order(db.Model):
    __tablename__ = 'orders'

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(UUID(as_uuid=True), unique=True, default=uuid.uuid4, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)

    # Order details
    order_type = db.Column(db.String(4), nullable=False, index=True)  # 'buy' or 'sell'
    pair = db.Column(db.String(20), nullable=False, index=True)
    price = db.Column(db.Numeric(20, 8), nullable=False, index=True)
    amount = db.Column(db.Numeric(20, 8), nullable=False)
    filled_amount = db.Column(db.Numeric(20, 8), default=0, nullable=False)

    # Order execution
    order_side = db.Column(db.String(10), default='limit')  # limit, market, stop
    time_in_force = db.Column(db.String(10), default='GTC')  # GTC, IOC, FOK

    # Status
    status = db.Column(db.String(25), default='open', nullable=False, index=True)
    # open, partially_filled, filled, cancelled, expired

    # Fees
    fee_paid = db.Column(db.Numeric(20, 8), default=0)
    fee_currency = db.Column(db.String(10))
    maker_fee_rate = db.Column(db.Numeric(10, 8))
    taker_fee_rate = db.Column(db.Numeric(10, 8))

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc), index=True)
    updated_at = db.Column(db.DateTime, default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))
    filled_at = db.Column(db.DateTime)
    expires_at = db.Column(db.DateTime)

    # Relationships
    maker_trades = db.relationship('Trade', foreign_keys='Trade.maker_order_id', backref='maker_order', lazy='dynamic')
    taker_trades = db.relationship('Trade', foreign_keys='Trade.taker_order_id', backref='taker_order', lazy='dynamic')

    __table_args__ = (
        db.Index('idx_order_pair_status_type', 'pair', 'status', 'order_type'),
        db.Index('idx_order_user_status', 'user_id', 'status'),
        db.Index('idx_order_pair_price_time', 'pair', 'price', 'created_at'),
        db.Index('idx_order_matching', 'pair', 'order_type', 'status', 'price', 'created_at'),
        db.Index('idx_order_user_active', 'user_id', 'status', 'created_at'),
        db.Index('idx_order_user_pair', 'user_id', 'pair'),
        db.Index('idx_order_status_updated', 'status', 'updated_at'),
    )

    @property
    def remaining_amount(self):
        return max(Decimal('0'), self.amount - (self.filled_amount or Decimal('0')))

    @property
    def fill_percentage(self):
        if self.amount > 0:
            return float((self.filled_amount or Decimal('0')) / self.amount * 100)
        return 0

    @property
    def is_complete(self):
        return self.status in ['filled', 'cancelled', 'expired']

    def can_be_cancelled(self):
        return self.status in ['open', 'partially_filled'] and self.remaining_amount > 0

    def to_dict(self):
        return {
            'id': self.id,
            'uuid': str(self.uuid),
            'order_type': self.order_type,
            'pair': self.pair,
            'price': float(self.price),
            'amount': float(self.amount),
            'filled_amount': float(self.filled_amount or 0),
            'remaining_amount': float(self.remaining_amount),
            'status': self.status,
            'fill_percentage': self.fill_percentage,
            'fee_paid': float(self.fee_paid or 0),
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }


class Trade(db.Model):
    """Trade execution records - TimescaleDB hypertable"""
    __tablename__ = 'trades'

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(UUID(as_uuid=True), unique=True, default=uuid.uuid4, index=True)

    # Orders involved in trade
    maker_order_id = db.Column(db.Integer, db.ForeignKey('orders.id'), nullable=False, index=True)
    taker_order_id = db.Column(db.Integer, db.ForeignKey('orders.id'), nullable=False, index=True)

    # Users involved
    maker_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    taker_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)

    # Trade details
    pair = db.Column(db.String(20), nullable=False, index=True)
    price = db.Column(db.Numeric(20, 8), nullable=False)
    amount = db.Column(db.Numeric(20, 8), nullable=False)
    
    # Trade value in quote currency
    trade_value = db.Column(db.Numeric(20, 8), nullable=False)

    # Fees (revenue for exchange)
    maker_fee = db.Column(db.Numeric(20, 8), default=0)
    taker_fee = db.Column(db.Numeric(20, 8), default=0)
    total_fee = db.Column(db.Numeric(20, 8), default=0)

    # Matching algorithm used
    matching_algorithm = db.Column(db.String(10), default='FIFO')

    # Timestamp for TimescaleDB
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc), nullable=False, index=True)

    # Relationships
    maker_user = db.relationship('User', foreign_keys=[maker_user_id])
    taker_user = db.relationship('User', foreign_keys=[taker_user_id])

    __table_args__ = (
        db.Index('idx_trade_pair_time', 'pair', 'created_at'),
        db.Index('idx_trade_users', 'maker_user_id', 'taker_user_id'),
        db.Index('idx_trade_price', 'pair', 'price', 'created_at'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'uuid': str(self.uuid),
            'pair': self.pair,
            'price': float(self.price),
            'amount': float(self.amount),
            'trade_value': float(self.trade_value),
            'maker_fee': float(self.maker_fee),
            'taker_fee': float(self.taker_fee),
            'total_fee': float(self.total_fee),
            'created_at': self.created_at.isoformat()
        }


class Transaction(db.Model):
    __tablename__ = 'transactions'

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(UUID(as_uuid=True), unique=True, default=uuid.uuid4, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)

    # Transaction details
    tx_type = db.Column(db.String(30), nullable=False, index=True)
    # deposit, withdrawal, fee, trade_fee, listing_fee, api_fee
    
    currency = db.Column(db.String(10), nullable=False, index=True)
    amount = db.Column(db.Numeric(20, 8), nullable=False)
    fee = db.Column(db.Numeric(20, 8), default=0)

    # Blockchain info
    blockchain = db.Column(db.String(20))  # ethereum, bitcoin, etc
    from_address = db.Column(db.String(255))
    to_address = db.Column(db.String(255))
    blockchain_tx_hash = db.Column(db.String(100), unique=True, index=True)
    confirmations = db.Column(db.Integer, default=0)
    required_confirmations = db.Column(db.Integer, default=12)

    # Status tracking
    status = db.Column(db.String(20), default='pending', index=True)
    # pending, processing, completed, failed, expired, cancelled
    
    # Reference data
    reference_id = db.Column(db.String(100))  # Order ID, Trade ID, etc
    notes = db.Column(db.Text)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc), index=True)
    updated_at = db.Column(db.DateTime, default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))
    completed_at = db.Column(db.DateTime)
    expires_at = db.Column(db.DateTime)

    __table_args__ = (
        db.Index('idx_transaction_user_status', 'user_id', 'status'),
        db.Index('idx_transaction_type_currency', 'tx_type', 'currency'),
        db.Index('idx_transaction_blockchain_hash', 'blockchain', 'blockchain_tx_hash'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'uuid': str(self.uuid),
            'type': self.tx_type,
            'currency': self.currency,
            'amount': float(self.amount),
            'fee': float(self.fee),
            'status': self.status,
            'blockchain_tx_hash': self.blockchain_tx_hash,
            'confirmations': self.confirmations,
            'created_at': self.created_at.isoformat(),
            'completed_at': self.completed_at.isoformat() if self.completed_at else None
        }


class KYC(db.Model):
    __tablename__ = 'kyc'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)

    # Personal information
    full_name = db.Column(db.String(100), nullable=False)
    date_of_birth = db.Column(db.Date, nullable=False)
    country = db.Column(db.String(2), nullable=False, index=True)
    address = db.Column(db.Text)
    phone = db.Column(db.String(20))

    # Document information
    id_type = db.Column(db.String(20), nullable=False)
    id_number = db.Column(db.String(50))
    id_expiry_date = db.Column(db.Date)
    
    # File paths (encrypted storage)
    id_front_path = db.Column(db.String(255), nullable=False)
    id_back_path = db.Column(db.String(255), nullable=False)
    selfie_path = db.Column(db.String(255), nullable=False)
    proof_of_address_path = db.Column(db.String(255))

    # Verification status
    status = db.Column(db.String(20), default='pending', index=True)
    # pending, under_review, approved, rejected, expired
    
    verification_level = db.Column(db.String(20), default='basic')
    # basic, enhanced, institutional
    
    rejection_reason = db.Column(db.Text)
    risk_score = db.Column(db.Integer, default=0)

    # Timestamps
    submitted_at = db.Column(db.DateTime, default=datetime.now(timezone.utc), index=True)
    reviewed_at = db.Column(db.DateTime)
    approved_at = db.Column(db.DateTime)
    expires_at = db.Column(db.DateTime)

    # Reviewer information
    reviewed_by = db.Column(db.Integer, db.ForeignKey('users.id'))

    # Relationships
    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('kyc_records', lazy='dynamic'))
    reviewer = db.relationship('User', foreign_keys=[reviewed_by])

    def to_dict(self):
        return {
            'id': self.id,
            'full_name': self.full_name,
            'date_of_birth': self.date_of_birth,
            'country': self.country,
            'address': self.address,
            'phone': self.phone,
            'id_type': self.id_type,
            'id_number': self.id_number,
            'status': self.status,
            'verification_level': self.verification_level,
            'submitted_at': self.submitted_at.isoformat(),
            'reviewed_at': self.reviewed_at.isoformat() if self.reviewed_at else None,
            'id_front_path': self.id_front_path,
            'id_back_path': self.id_back_path,
            'selfie_path': self.selfie_path,
            'proof_of_address_path': self.proof_of_address_path,
            "photos": [
                "\\" + self.id_front_path,
                "\\" + self.id_back_path,
                "\\" + self.selfie_path,
                "\\" + self.proof_of_address_path
            ]
        }


class OrderBook(db.Model):
    """TimescaleDB hypertable for order book snapshots"""
    __tablename__ = 'orderbook_snapshots'

    id = db.Column(db.Integer, primary_key=True)
    pair = db.Column(db.String(20), nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=datetime.now(timezone.utc), nullable=False, index=True)

    # Best prices and volumes
    best_bid_price = db.Column(db.Numeric(20, 8))
    best_ask_price = db.Column(db.Numeric(20, 8))
    best_bid_volume = db.Column(db.Numeric(20, 8))
    best_ask_volume = db.Column(db.Numeric(20, 8))

    # Market metrics
    spread = db.Column(db.Numeric(20, 8))
    spread_percentage = db.Column(db.Numeric(10, 4))
    mid_price = db.Column(db.Numeric(20, 8))

    # Depth metrics
    total_bid_volume = db.Column(db.Numeric(20, 8))
    total_ask_volume = db.Column(db.Numeric(20, 8))
    order_count_bids = db.Column(db.Integer)
    order_count_asks = db.Column(db.Integer)

    __table_args__ = (
        db.Index('idx_orderbook_pair_timestamp', 'pair', 'timestamp'),
    )


class MarketData(db.Model):
    """24h market statistics - TimescaleDB hypertable"""
    __tablename__ = 'market_data'

    id = db.Column(db.Integer, primary_key=True)
    pair = db.Column(db.String(20), nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=datetime.now(timezone.utc), nullable=False, index=True)

    # OHLCV data
    open_price = db.Column(db.Numeric(20, 8))
    high_price = db.Column(db.Numeric(20, 8))
    low_price = db.Column(db.Numeric(20, 8))
    close_price = db.Column(db.Numeric(20, 8))
    volume = db.Column(db.Numeric(20, 8))

    # 24h statistics
    price_change = db.Column(db.Numeric(20, 8))
    price_change_percent = db.Column(db.Numeric(10, 4))
    volume_24h = db.Column(db.Numeric(20, 8))
    high_24h = db.Column(db.Numeric(20, 8))
    low_24h = db.Column(db.Numeric(20, 8))

    # Trade statistics
    trade_count = db.Column(db.Integer, default=0)
    
    __table_args__ = (
        db.Index('idx_market_data_pair_time', 'pair', 'timestamp'),
    )


class PlatformWallet(db.Model):
    """Platform wallet for collecting fees and revenue"""
    __tablename__ = 'platform_wallets'

    id = db.Column(db.Integer, primary_key=True)
    currency = db.Column(db.String(10), nullable=False, unique=True, index=True)

    # Balances
    balance = db.Column(db.Numeric(20, 8), default=0, nullable=False)

    # Revenue tracking
    trading_fees_collected = db.Column(db.Numeric(20, 8), default=0)
    withdrawal_fees_collected = db.Column(db.Numeric(20, 8), default=0)
    listing_fees_collected = db.Column(db.Numeric(20, 8), default=0)
    total_revenue = db.Column(db.Numeric(20, 8), default=0)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    last_updated = db.Column(db.DateTime, default=datetime.now(timezone.utc))

    def add_revenue(self, amount: Decimal, revenue_type: str):
        """Add revenue to platform wallet"""
        self.balance += amount
        self.total_revenue += amount

        if revenue_type == 'trading_fee':
            self.trading_fees_collected += amount
        elif revenue_type == 'withdrawal_fee':
            self.withdrawal_fees_collected += amount
        elif revenue_type == 'listing_fee':
            self.listing_fees_collected += amount

        self.last_updated = datetime.now(timezone.utc)

    def to_dict(self):
        return {
            'currency': self.currency,
            'balance': float(self.balance),
            'trading_fees': float(self.trading_fees_collected),
            'withdrawal_fees': float(self.withdrawal_fees_collected),
            'total_revenue': float(self.total_revenue),
            'last_updated': self.last_updated.isoformat()
        }


class SystemMetrics(db.Model):
    """System performance metrics"""
    __tablename__ = 'system_metrics'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.now(timezone.utc), nullable=False, index=True)
    
    # Performance metrics
    active_users = db.Column(db.Integer, default=0)
    total_orders = db.Column(db.Integer, default=0)
    total_trades = db.Column(db.Integer, default=0)
    trading_volume_24h = db.Column(db.Numeric(20, 8), default=0)
    
    # Revenue metrics
    fees_collected_24h = db.Column(db.Numeric(20, 8), default=0)
    
    # System health
    avg_response_time_ms = db.Column(db.Integer)
    error_rate_percent = db.Column(db.Numeric(5, 2))