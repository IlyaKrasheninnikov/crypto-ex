"""
Database initialization script
Creates tables and initializes TimescaleDB
"""
import logging
import os
import uuid
from datetime import datetime, timezone

from flask import Flask

from models import db, User, Wallet, EthereumWallet, PlatformWallet
from config import Config
from decimal import Decimal

from services.wallet_service import init_wallet_service

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
logger = logging.getLogger(__name__)

def init_database(socketio):
    """Initialize database with tables and test data"""
    with app.app_context():

        global wallet_service
        wallet_service = init_wallet_service(db, socketio)

        logger.info("Creating database tables...")
        db.create_all()

        logger.info("Creating admin user...")
        create_platform_admin()

        logger.info("Creating test users with balances...")
        create_test_users()

        logger.info("✓ Database initialization complete!")


def create_platform_admin():
    """
    Create platform admin account
    Admin's wallets serve as platform fee collection wallets
    """
    logger.info("\n" + "=" * 60)
    logger.info("Creating Platform Admin Account")
    logger.info("=" * 60)

    with app.app_context():
        try:
            # Check if admin already exists
            existing_admin = User.query.filter_by(is_admin=True).first()
            if existing_admin:
                logger.info(f"\n⚠️  Admin already exists: {existing_admin.username}")
                return existing_admin

            # Admin credentials (CHANGE THESE IN PRODUCTION!)
            ADMIN_EMAIL = os.getenv('ADMIN_EMAIL', 'admin@nexuscrypt.com')
            ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'platform_admin')
            ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'Admin123!ChangeMe')

            logger.info(f"\n📧 Email: {ADMIN_EMAIL}")
            logger.info(f"👤 Username: {ADMIN_USERNAME}")
            logger.info(f"🔑 Password: {ADMIN_PASSWORD}")
            logger.info("\n⚠️  CHANGE THESE CREDENTIALS IN PRODUCTION!\n")

            # Create Ethereum wallet for admin
            logger.info("🔐 Creating Ethereum wallet...")
            wallet_data = wallet_service.create_user_wallet()

            # Create admin user
            logger.info("👨‍💼 Creating admin user...")
            admin = User(
                email=ADMIN_EMAIL.lower(),
                username=ADMIN_USERNAME,
                uuid=uuid.uuid4(),
                is_active=True,
                is_verified=True,
                is_admin=True,
                kyc_status='approved',
                kyc_verified_at=datetime.now(timezone.utc),
                vip_tier='ADMIN',
                created_at=datetime.now(timezone.utc),
                full_name='Platform Administrator',
                country='US'
            )
            admin.set_password(ADMIN_PASSWORD)

            db.session.add(admin)
            db.session.flush()  # Get admin.id

            logger.info(f"   ✅ Admin ID: {admin.id}")

            # Create Ethereum wallet for admin
            logger.info("🔗 Linking Ethereum wallet...")
            eth_wallet = EthereumWallet(
                user_id=admin.id,
                address=wallet_data['address'],
                encrypted_private_key=EthereumWallet.encrypt_private_key(
                    wallet_data['private_key']
                ),
                network='ethereum',
                is_active=True,
                created_at=datetime.now(timezone.utc)
            )
            db.session.add(eth_wallet)

            logger.info(f"   ✅ Address: {wallet_data['address']}")

            # Create platform currency wallets (these collect fees)
            logger.info("💰 Creating platform fee collection wallets...")

            platform_currencies = {
                'USDT': Decimal('0'),  # Start with 0, will collect fees
                'ETH': Decimal('0'),
                'BTC': Decimal('0'),
                'SOL': Decimal('0'),
                'ADA': Decimal('0'),
                'DOT': Decimal('0'),
                'BNB': Decimal('0'),
                'MATIC': Decimal('0')
            }

            admin_wallets = {}

            for currency, initial_balance in platform_currencies.items():
                # Create admin's wallet (used as platform wallet)
                wallet = Wallet(
                    user_id=admin.id,
                    currency=currency,
                    balance=initial_balance,
                    locked_balance=Decimal('0'),
                    total_deposited=Decimal('0'),
                    total_withdrawn=Decimal('0'),
                    is_active=True,
                    wallet_type='platform',  # Mark as platform wallet
                    created_at=datetime.now(timezone.utc),
                    last_updated=datetime.now(timezone.utc)
                )
                db.session.add(wallet)
                db.session.flush()

                admin_wallets[currency] = wallet

                # Create PlatformWallet record linking to admin's wallet
                platform_wallet = PlatformWallet(
                    currency=currency,
                    balance=initial_balance,
                    trading_fees_collected=Decimal('0'),
                    withdrawal_fees_collected=Decimal('0'),
                    listing_fees_collected=Decimal('0'),
                    total_revenue=Decimal('0'),
                    created_at=datetime.now(timezone.utc),
                    last_updated=datetime.now(timezone.utc)
                )
                db.session.add(platform_wallet)

                logger.info(f"   ✅ {currency} wallet created")

            # Commit all changes
            db.session.commit()

            # Success summary
            logger.info("\n" + "=" * 60)
            logger.info("✅ PLATFORM ADMIN CREATED SUCCESSFULLY!")
            logger.info("=" * 60)
            logger.info(f"\n📊 Account Details:")
            logger.info(f"   • Admin ID: {admin.id}")
            logger.info(f"   • Username: {ADMIN_USERNAME}")
            logger.info(f"   • Email: {ADMIN_EMAIL}")
            logger.info(f"   • Password: {ADMIN_PASSWORD}")
            logger.info(f"\n🔗 Blockchain:")
            logger.info(f"   • Network: Ethereum")
            logger.info(f"   • Address: {wallet_data['address']}")
            logger.info(f"\n💰 Platform Wallets Created:")
            for currency in platform_currencies.keys():
                logger.info(f"   • {currency}: Ready for fee collection")
            logger.info("\n" + "=" * 60)
            logger.info("⚠️  IMPORTANT: Change admin password after first login!")
            logger.info("🔐 Store private key securely - never share it!")
            logger.info("=" * 60 + "\n")

            return admin

        except Exception as e:
            db.session.rollback()
            logger.info(f"\n❌ Error creating admin: {e}")
            raise


def create_test_users():
    """Create test users with trading balances"""
    test_users = [
        {
            'email': 'trader1@test.com',
            'username': 'trader1',
            'password': 'password123'
        },
        {
            'email': 'trader2@test.com',
            'username': 'trader2',
            'password': 'password123'
        },
        {
            'email': 'trader3@test.com',
            'username': 'trader3',
            'password': 'password123'
        },
    ]

    for user_data in test_users:
        user = User.query.filter_by(email=user_data['email']).first()
        if not user:
            user = User(
                email=user_data['email'],
                username=user_data['username'],
                uuid=uuid.uuid4(),  # ADD THIS - it's also required
                is_verified=True,
                is_active=True,  # ADD THIS - probably required too
                kyc_status='approved'
            )
            user.set_password(user_data['password'])
            db.session.add(user)
            db.session.flush()  # Get user.id before creating wallets

            # Create wallets with test balances
            currencies_and_balances = {
                'BTC': Decimal('1.0'),
                'ETH': Decimal('10.0'),
                'USDT': Decimal('100000.0'),
                'BNB': Decimal('50.0'),
                'XRP': Decimal('10000.0'),
                'SOL': Decimal('100.0')
            }

            for currency, balance in currencies_and_balances.items():
                wallet = Wallet(
                    user_id=user.id,
                    currency=currency,
                    balance=balance,
                    locked_balance=Decimal('0')
                )
                db.session.add(wallet)

            db.session.commit()
            logger.info(f"✓ Test user created: {user_data['username']} ({user_data['email']}) with trading balances")
