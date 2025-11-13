import os
from decimal import Decimal
from datetime import timedelta

class Config:
    """Base configuration class with comprehensive settings"""
    
    # Flask Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-key-change-in-production-IMMEDIATELY'
    
    # Database Configuration - TimescaleDB
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'postgresql://postgres:password@localhost:5432/crypto_exchange'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': 20,
        'pool_recycle': 3600,
        'pool_pre_ping': True,
        'max_overflow': 30
    }
    
    # Redis Configuration
    REDIS_URL = os.environ.get('REDIS_URL') or 'redis://localhost:6379/0'
    CACHE_TYPE = 'redis'
    CACHE_REDIS_URL = REDIS_URL
    
    # Security Configuration
    WTF_CSRF_ENABLED = True
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
    
    # Rate Limiting
    RATELIMIT_STORAGE_URL = REDIS_URL
    RATELIMIT_DEFAULT = "1000 per hour"
    RATELIMIT_HEADERS_ENABLED = True
    
    # JWT Configuration
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET') or SECRET_KEY
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    
    # File Upload Configuration
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf', 'doc', 'docx'}
    
    # Blockchain Configuration
    WEB3_PROVIDER_URL = os.environ.get('WEB3_PROVIDER_URL') or 'https://mainnet.infura.io/v3/YOUR_PROJECT_ID'
    ETHEREUM_NETWORK = os.environ.get('ETHEREUM_NETWORK') or 'mainnet'
    
    # Hot Wallet (for operational transactions)
    HOT_WALLET_ADDRESS = os.environ.get('HOT_WALLET_ADDRESS')
    HOT_WALLET_PRIVATE_KEY = os.environ.get('HOT_WALLET_PRIVATE_KEY')
    
    # Cold Wallet (for large fund storage)
    COLD_WALLET_ADDRESS = os.environ.get('COLD_WALLET_ADDRESS')
    COLD_WALLET_THRESHOLD = Decimal('10.0')  # ETH threshold to move to cold storage
    
    # Trading Configuration
    SUPPORTED_CURRENCIES = ['BTC', 'ETH', 'USDT', 'BNB', 'XRP', 'SOL', 'ADA', 'DOT', 'MATIC']
    TRADING_PAIRS = [
        'BTC/USDT', 'ETH/USDT', 'BNB/USDT', 'XRP/USDT', 'SOL/USDT',
        'ADA/USDT', 'DOT/USDT', 'MATIC/USDT', 'ETH/BTC', 'BNB/BTC'
    ]
    
    # Fee Structure (Revenue Generation)
    MAKER_FEE_RATE = Decimal('0.001')  # 0.1%
    TAKER_FEE_RATE = Decimal('0.002')  # 0.2%
    WITHDRAWAL_FEE_RATE = Decimal('0.0005')  # 0.05%
    
    # VIP Fee Tiers (Volume-based)
    VIP_TIERS = {
        'VIP0': {'volume_threshold': Decimal('0'), 'maker_fee': Decimal('0.001'), 'taker_fee': Decimal('0.002')},
        'VIP1': {'volume_threshold': Decimal('10000'), 'maker_fee': Decimal('0.0009'), 'taker_fee': Decimal('0.0018')},
        'VIP2': {'volume_threshold': Decimal('50000'), 'maker_fee': Decimal('0.0008'), 'taker_fee': Decimal('0.0016')},
        'VIP3': {'volume_threshold': Decimal('100000'), 'maker_fee': Decimal('0.0006'), 'taker_fee': Decimal('0.0012')}
    }
    
    # Order Matching Engine Configuration
    MATCHING_ALGORITHM = 'FIFO'  # FIFO or PRO_RATA
    MAX_ORDER_SIZE = Decimal('1000000')  # Maximum order size in USDT
    MIN_ORDER_SIZE = Decimal('10')  # Minimum order size in USDT
    PRICE_PRECISION = 8
    AMOUNT_PRECISION = 8
    
    # Risk Management
    MAX_ORDERS_PER_USER = 100
    MAX_DAILY_WITHDRAWAL = Decimal('50000')  # USDT
    WITHDRAWAL_CONFIRMATION_BLOCKS = 12
    
    # KYC/AML Configuration
    KYC_REQUIRED_FOR_TRADING = True
    KYC_WITHDRAWAL_LIMIT_UNVERIFIED = Decimal('1000')  # Daily limit for unverified users
    KYC_WITHDRAWAL_LIMIT_VERIFIED = Decimal('100000')  # Daily limit for verified users
    
    # Email Configuration
    MAIL_SERVER = os.environ.get('MAIL_SERVER') or 'smtp.gmail.com'
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 587)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', 'on', '1']
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    
    # WebSocket Configuration
    SOCKETIO_ASYNC_MODE = 'redis'
    SOCKETIO_MESSAGE_QUEUE = REDIS_URL
    
    # Monitoring & Logging
    LOG_LEVEL = os.environ.get('LOG_LEVEL') or 'INFO'
    LOG_FILE = os.environ.get('LOG_FILE') or 'exchange.log'
    
    # External APIs
    BINANCE_API_KEY = os.environ.get('BINANCE_API_KEY')
    BINANCE_SECRET_KEY = os.environ.get('BINANCE_SECRET_KEY')
    COINMARKETCAP_API_KEY = os.environ.get('COINMARKETCAP_API_KEY')
    
    # Celery Configuration (for background tasks)
    CELERY_BROKER_URL = REDIS_URL
    CELERY_RESULT_BACKEND = REDIS_URL
    CELERY_TASK_SERIALIZER = 'json'
    CELERY_RESULT_SERIALIZER = 'json'
    CELERY_ACCEPT_CONTENT = ['json']
    CELERY_TIMEZONE = 'UTC'
    
    # Additional Revenue Streams
    LISTING_FEE = Decimal('50000')  # Fee for new token listings
    API_RATE_LIMIT_PREMIUM = Decimal('100')  # Monthly fee for higher API limits
    MARGIN_TRADING_INTEREST_RATE = Decimal('0.02')  # 2% daily interest for margin trading