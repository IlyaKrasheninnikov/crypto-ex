import requests
from flask import Flask, jsonify, request, render_template, session, redirect, url_for, send_from_directory
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_login import LoginManager, current_user
from flask_jwt_extended import JWTManager, create_access_token
from flask import flash

from init_db import init_database
from services.deposit_monitor import start_deposit_monitor
from services.trade_executor import TradeExecutor
from sqlalchemy import and_
import os
import logging
from datetime import datetime, timezone, timedelta
from decimal import Decimal
import uuid
from functools import wraps
from werkzeug.utils import secure_filename

from services.matching_engine import matching_engine
from services.wallet_service import init_wallet_service
from services.price_service import PriceService
from config import Config
from models import db, User, Order, Transaction, EthereumWallet, Wallet, KYC, Trade

from dotenv import load_dotenv
load_dotenv()

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)

cors = CORS(app, resources={
    r"/api/*": {
        "origins": ["*"],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "X-User-ID"]
    }
})

# Flask-Limiter with Redis storage
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["1000 per hour"],
    storage_uri=Config.REDIS_URL,
    storage_options={"socket_connect_timeout": 30},
    strategy="fixed-window"
)

jwt = JWTManager(app)

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

price_service = PriceService()

# Configure logging with UTF-8 encoding
os.makedirs('logs', exist_ok=True)
logging.basicConfig(
    level=getattr(logging, os.getenv('LOG_LEVEL', 'INFO')),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/exchange.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

wallet_service = init_wallet_service(db, socketio)

with app.app_context():
    init_database(socketio)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    from models import User
    return User.query.get(int(user_id))


def require_kyc(f):
    """Decorator to require KYC verification"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = request.headers.get('X-User-ID')
        if not user_id:
            return jsonify({'error': 'Authentication required'}), 401

        user = User.query.get(int(user_id))
        if not user:
            return jsonify({'error': 'User not found'}), 404

        if user.kyc_status != 'approved':
            return jsonify({
                'error': 'KYC verification required',
                'kyc_status': user.kyc_status,
                'message': 'Please complete KYC verification to trade'
            }), 403

        return f(*args, **kwargs)

    return decorated_function


def require_auth(f):
    """Decorator for authenticated endpoints"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = request.headers.get('X-User-ID')
        if not user_id:
            return jsonify({'error': 'Authentication required'}), 401

        user = User.query.filter_by(id=int(user_id)).first()
        if not user or not user.is_active:
            return jsonify({'error': 'Invalid or inactive user'}), 401

        return f(user_id, *args, **kwargs)

    return decorated_function


def validate_trading_pair(pair: str) -> bool:
    """Validate trading pair format"""
    valid_pairs = ['ETHUSDT', 'BTCUSDT', 'SOLUSDT', 'ADAUSDT', 'DOTUSDT']
    return pair.upper() in valid_pairs


@app.route('/health')
def health_check():
    """Health check endpoint for load balancer"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'version': '1.0.0',
        'services': {
            'matching_engine': 'online',
            'wallet_service': 'online',
            'price_service': 'online',
            'database': 'online'
        }
    }), 200


@app.route('/get_new_listings')
def get_new_listings():
    """Get new cryptocurrency listings from Binance"""
    try:
        url = "https://www.binance.com/bapi/composite/v1/public/promo/cmc/cryptocurrency/listings/new?limit=10&start=1"
        response = requests.get(url, timeout=5)
        data = response.json()
        return jsonify(data["data"]["body"]["data"][:3])
    except Exception as e:
        logger.error(f"Error fetching new listings: {e}")
        return jsonify([])

@app.route('/get_top_gainers')
def get_top_gainers():
    """Get top gaining cryptocurrencies"""
    try:
        url = "https://www.binance.com/bapi/composite/v1/public/promo/cmc/cryptocurrency/spotlight?dataType=2&timeframe=7d"
        response = requests.get(url, timeout=5)
        data = response.json()
        return jsonify(data["data"]["body"]["data"]["gainerList"][:3])
    except Exception as e:
        logger.error(f"Error fetching top gainers: {e}")
        return jsonify([])

@app.route('/get_popular_coins')
def get_popular_coins():
    """Get popular cryptocurrencies"""
    try:
        timeframe = request.args.get('timeframe', '24h')
        url = f"https://www.binance.com/bapi/composite/v1/public/promo/cmc/cryptocurrency/spotlight?dataType=4&timeframe={timeframe}"
        response = requests.get(url, timeout=5)
        data = response.json()
        return jsonify(data["data"]["body"]["data"]["mostVisitedList"][:7])
    except Exception as e:
        logger.error(f"Error fetching popular coins: {e}")
        return jsonify([])

@app.route('/coin_data/<symbol>')
def get_coin_data(symbol):
    """Get coin data"""
    try:
        url = f"https://www.binance.com/bapi/composite/v1/public/promo/cmc/cryptocurrency/quotes/latest?symbol={symbol}"
        price_url = f"https://api.binance.com/api/v1/ticker/24hr?symbol={symbol.upper()}USDT"

        response = requests.get(url, timeout=5)
        data = response.json()
        first_entry = data["data"]["body"]["data"][symbol.upper()][0]

        if symbol.upper() == "USDT":
            price = 1
        else:
            price_data = requests.get(price_url, timeout=5).json()
            price = price_data.get("lastPrice")

        return jsonify({
            "name": first_entry["name"],
            "symbol": first_entry["symbol"],
            "price": price,
            "id": first_entry["id"]
        })
    except Exception as e:
        logger.error(f"Error fetching coin data: {e}")
        return jsonify({"error": "Data not available"}), 404

@app.route('/get_graph/<coin_id>')
def get_graph_data(coin_id):
    """Get graph data for coin"""
    try:
        timeframe = request.args.get('timeframe', '1D')
        url = f"https://www.binance.com/bapi/composite/v1/public/promo/cmc/cryptocurrency/detail/chart?id={coin_id}&range={timeframe}"
        response = requests.get(url, timeout=5)
        data = response.json()
        return jsonify(data["data"]["body"]["data"]["points"])
    except Exception as e:
        logger.error(f"Error fetching graph data: {e}")
        return jsonify([])

@app.route('/price/<symbol>')
def get_coin_price(symbol):
    """Get coin price page"""
    try:
        price_url = f"https://api.binance.com/api/v3/ticker/price?symbol={symbol.upper()}USDT"
        price_data = requests.get(price_url, timeout=5).json()

        if price_data.get("price") is None:
            return render_template("not_listed.html", init_symbol=symbol)

        return render_template('coin_details.html', init_symbol=symbol)
    except:
        return render_template("not_listed.html", init_symbol=symbol)

@app.route('/pair_price/<symbol>')
def get_pair_price(symbol):
    """Get trading pair price"""
    try:
        price_url = f"https://api.binance.com/api/v3/ticker/price?symbol={symbol}"
        price_data = requests.get(price_url, timeout=5).json()
        return jsonify({"price": price_data.get("price")})
    except Exception as e:
        logger.error(f"Error fetching pair price: {e}")
        return jsonify({"error": "Price not available"}), 404


@app.route('/api/auth/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    """
    User registration endpoint with proper transaction handling
    Supports both HTML form (GET/POST) and JSON API (POST)
    """
    if request.method == 'GET':
        logger.info("GET request to /api/auth/register - returning registration page")
        return render_template('register.html')

    logger.info(
        f"POST request to /api/auth/register - Content-Type: {request.content_type}, is_json: {request.is_json}")

    try:
        if request.is_json:
            data = request.get_json()
            logger.info("Processing as JSON request")
        else:
            data = request.form.to_dict()
            logger.info(f"Processing as form request - Data keys: {data.keys()}")

        email = data.get('email', '').strip()
        username = data.get('username', '').strip()
        password = data.get('password', '')

        logger.info(f"Registration attempt - email: {email}, username: {username}")

        if not all([email, username, password]):
            error_msg = 'All fields are required'
            logger.warning(f"Validation failed: {error_msg}")
            if request.is_json:
                return jsonify({'error': error_msg}), 400
            return render_template('register.html', error=error_msg), 400

        import re
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_regex, email):
            error_msg = 'Invalid email format'
            logger.warning(f"Validation failed: {error_msg} for email: {email}")
            if request.is_json:
                return jsonify({'error': error_msg}), 400
            return render_template('register.html', error=error_msg), 400

        if len(username) < 3 or len(username) > 30:
            error_msg = 'Username must be between 3 and 30 characters'
            logger.warning(f"Validation failed: {error_msg}")
            if request.is_json:
                return jsonify({'error': error_msg}), 400
            return render_template('register.html', error=error_msg), 400

        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            error_msg = 'Username can only contain letters, numbers, and underscores'
            logger.warning(f"Validation failed: {error_msg}")
            if request.is_json:
                return jsonify({'error': error_msg}), 400
            return render_template('register.html', error=error_msg), 400

        if len(password) < 8:
            error_msg = 'Password must be at least 8 characters'
            logger.warning(f"Validation failed: {error_msg}")
            if request.is_json:
                return jsonify({'error': error_msg}), 400
            return render_template('register.html', error=error_msg), 400

        if not any(c.isupper() for c in password):
            error_msg = 'Password must contain at least one uppercase letter'
            logger.warning(f"Validation failed: {error_msg}")
            if request.is_json:
                return jsonify({'error': error_msg}), 400
            return render_template('register.html', error=error_msg), 400

        if not any(c.isdigit() for c in password):
            error_msg = 'Password must contain at least one number'
            logger.warning(f"Validation failed: {error_msg}")
            if request.is_json:
                return jsonify({'error': error_msg}), 400
            return render_template('register.html', error=error_msg), 400

        existing_user_email = User.query.filter(
            db.func.lower(User.email) == email.lower()
        ).first()

        if existing_user_email:
            error_msg = 'Email already registered'
            logger.warning(f"Registration failed: {error_msg} for {email}")
            if request.is_json:
                return jsonify({'error': error_msg}), 409
            flash('Email already registered!', 'error')
            return render_template('register.html', error=error_msg), 409

        existing_user_username = User.query.filter(
            db.func.lower(User.username) == username.lower()
        ).first()

        if existing_user_username:
            error_msg = 'Username already taken'
            logger.warning(f"Registration failed: {error_msg} for {username}")
            if request.is_json:
                return jsonify({'error': error_msg}), 409
            return render_template('register.html', error=error_msg), 409

        try:
            logger.info(f"Creating wallet for user: {username}")
            wallet_data = wallet_service.create_user_wallet()

            if not wallet_data or 'address' not in wallet_data or 'private_key' not in wallet_data:
                raise ValueError("Wallet service returned invalid data")

            db.session.begin_nested()

            user = User(
                email=email.lower(),
                username=username,
                uuid=uuid.uuid4(),
                is_active=True,
                is_verified=False,
                kyc_status='not_submitted',
                vip_tier='VIP0',
                created_at=datetime.now(timezone.utc)
            )
            user.set_password(password)

            db.session.add(user)
            db.session.flush()

            logger.info(f"User created with ID: {user.id}")

            eth_wallet = EthereumWallet(
                user_id=user.id,
                address=wallet_data['address'],
                encrypted_private_key=EthereumWallet.encrypt_private_key(
                    wallet_data['private_key']
                ),
                network='ethereum',
                is_active=True,
                created_at=datetime.now(timezone.utc)
            )
            db.session.add(eth_wallet)

            logger.info(f"Ethereum wallet created for user {user.id}: {wallet_data['address']}")

            initial_balances = {
                #'USDT': Decimal('100000.0'),
                'USDT': Decimal('0.0'),
                'ETH': Decimal('0.0'),
                'BTC': Decimal('0.0'),
                #'SOL': Decimal('20000.0'),
                'SOL': Decimal('0.0'),
                'ADA': Decimal('0.0'),
                'DOT': Decimal('0.0')
            }

            for currency, initial_balance in initial_balances.items():
                wallet = Wallet(
                    user_id=user.id,
                    currency=currency,
                    balance=initial_balance,
                    locked_balance=Decimal('0'),
                    total_deposited=Decimal('0'),
                    total_withdrawn=Decimal('0'),
                    is_active=True,
                    created_at=datetime.now(timezone.utc),
                    last_updated=datetime.now(timezone.utc)
                )
                db.session.add(wallet)

            logger.info(f"Created {len(initial_balances)} currency wallets for user {user.id}")

            db.session.commit()

            logger.info(f"[SUCCESS] Successfully registered user: {username} (ID: {user.id})")

            if request.is_json:
                logger.info("Returning JSON response with 201")
                return jsonify({
                    'success': True,
                    'user': {
                        'id': user.id,
                        'username': user.username,
                        'email': user.email,
                        'deposit_address': wallet_data['address'],
                        'created_at': user.created_at.isoformat()
                    },
                    'wallets': {
                        'ethereum_address': wallet_data['address'],
                        'balances': {k: float(v) for k, v in initial_balances.items()}
                    },
                    'message': 'Registration successful'
                }), 201
            else:
                logger.info("Returning redirect to login page")
                session['registration_success'] = True
                session['registered_username'] = username
                flash('Registration successful! Please login with your credentials.', 'success')
                return redirect(url_for('login')), 303

        except Exception as db_error:
            db.session.rollback()
            logger.error(f"[ERROR] Database error during registration: {db_error}", exc_info=True)

            error_msg = 'Registration failed due to database error'
            if request.is_json:
                return jsonify({
                    'error': error_msg,
                    'details': str(db_error) if app.debug else None
                }), 500
            return render_template('register.html', error=error_msg), 500

    except ValueError as ve:
        logger.error(f"[ERROR] Validation error: {ve}")
        error_msg = str(ve)
        if request.is_json:
            return jsonify({'error': error_msg}), 400
        return render_template('register.html', error=error_msg), 400

    except Exception as e:
        logger.error(f"[ERROR] Unexpected registration error: {e}", exc_info=True)

        error_msg = 'Registration failed. Please try again later.'
        if request.is_json:
            return jsonify({
                'error': error_msg,
                'details': str(e) if app.debug else None
            }), 500
        return render_template('register.html', error=error_msg), 500


@app.route('/api/auth/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if request.method == 'GET':
        return render_template('login.html')

    try:
        if request.is_json:
            data = request.get_json()
            return_json = True
        else:
            data = request.form.to_dict()
            return_json = False

        username = data.get('username') or data.get('email')
        password = data.get('password')

        if not username or not password:
            if return_json:
                return jsonify({'error': 'Username/Email and password required'}), 400
            flash('Username/Email and password are required', 'error')
            return render_template('login.html', error='Username/Email and password required')

        user = User.query.filter(
            (User.username == username) | (User.email == username)
        ).first()

        if not user or not user.check_password(password):
            if user:
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= 5:
                    user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=30)
                db.session.commit()

            if return_json:
                return jsonify({'error': 'Invalid credentials'}), 401
            flash('Invalid credentials. Please check your email/username and password.', 'error')
            return render_template('login.html', error='Invalid credentials')

        if user.is_account_locked():
            if return_json:
                return jsonify({'error': 'Account temporarily locked'}), 403
            flash('Account temporarily locked due to multiple failed login attempts', 'error')
            return render_template('login.html', error='Account temporarily locked')

        user.failed_login_attempts = 0
        user.last_login = datetime.now(timezone.utc)
        db.session.commit()

        access_token = create_access_token(identity=str(user.id))

        if return_json:
            return jsonify({
                'success': True,
                'access_token': access_token,
                'user': user.to_dict()
            }), 200
        else:
            from flask_login import login_user
            login_user(user, remember=data.get('remember') == 'on')

            session['access_token'] = access_token
            session['user_id'] = user.id

            return redirect(url_for('index'))

    except Exception as e:
        logger.error(f"Login error: {e}", exc_info=True)
        if return_json:
            return jsonify({'error': 'Login failed'}), 500
        flash('An error occurred during login. Please try again.', 'error')
        return render_template('login.html', error='Login failed')


@app.route('/api/wallet/create', methods=['POST'])
def create_wallet():
    """Create new wallet for user - no auth required for initial setup"""
    try:
        data = request.get_json(silent=True) or {}
        network = data.get('network', 'ethereum')

        wallet_data = wallet_service.create_user_wallet()

        return jsonify({
            'success': True,
            'address': wallet_data['address'],
            'network': network,
            'faucet_urls': {
                'ethereum': 'https://sepoliafaucet.com/',
                'polygon': 'https://faucet.polygon.technology/',
                'bsc': 'https://testnet.binance.org/faucet-smart'
            }
        }), 201
    except Exception as e:
        logger.error(f"Wallet creation error: {e}", exc_info=True)
        return jsonify({'error': 'Failed to create wallet'}), 500


@app.route('/api/wallet/balance', methods=['GET'])
def get_wallet_balance():
    """Get wallet balance"""
    try:
        address = request.args.get('address')
        network = request.args.get('network', 'ethereum')

        if not address:
            return jsonify({'error': 'Address required'}), 400

        eth_balance = wallet_service.get_balance(address, 'ETH')
        usdt_balance = wallet_service.get_balance(address, 'USDT')

        return jsonify({
            'address': address,
            'network': network,
            'native': float(eth_balance),
            'usdt': float(usdt_balance),
            'balances': {
                'ETH': float(eth_balance),
                'USDT': float(usdt_balance)
            }
        }), 200

    except Exception as e:
        logger.error(f"Balance check error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/wallet/deposit', methods=['POST'])
@require_auth
def simulate_deposit(user_id: str):
    """Simulate deposit for demo purposes with proper user authentication"""
    try:
        data = request.get_json()
        amount = Decimal(str(data.get('amount', 0)))
        currency = data.get('currency', 'USDT').upper()

        if amount <= 0:
            return jsonify({'error': 'Invalid deposit amount', 'success': False}), 400

        valid_currencies = ['USDT', 'ETH', 'BTC', 'SOL', 'ADA', 'DOT']
        if currency not in valid_currencies:
            return jsonify({
                'error': f'Invalid currency. Supported: {", ".join(valid_currencies)}',
                'success': False
            }), 400

        wallet = Wallet.query.filter_by(
            user_id=int(user_id),
            currency=currency,
            is_active=True
        ).first()

        if not wallet:
            return jsonify({'error': f'{currency} wallet not found', 'success': False}), 404

        transaction_id = str(uuid.uuid4())

        old_balance = wallet.balance
        wallet.balance += amount
        wallet.total_deposited += amount
        wallet.last_updated = datetime.now(timezone.utc)

        transaction = Transaction(
            user_id=int(user_id),
            tx_type='deposit',
            currency=currency,
            amount=amount,
            status='completed',
            blockchain_tx_hash=transaction_id,
            from_address='demo_deposit_system',
            to_address='user_wallet',
            confirmations=1,
            created_at=datetime.now(timezone.utc)
        )

        db.session.add(transaction)
        db.session.commit()

        user_wallets = Wallet.query.filter_by(
            user_id=int(user_id),
            is_active=True
        ).all()

        balances = {w.currency: float(w.balance) for w in user_wallets}

        socketio.emit('balance_update', {
            'user_id': user_id,
            'currency': currency,
            'amount': float(amount),
            'old_balance': float(old_balance),
            'new_balance': float(wallet.balance),
            'balances': balances,
            'type': 'deposit',
            'transaction_id': transaction_id
        }, namespace='/')

        logger.info(f"Demo deposit: User {user_id} deposited {amount} {currency}")

        return jsonify({
            'success': True,
            'transaction_id': transaction_id,
            'amount': float(amount),
            'currency': currency,
            'old_balance': float(old_balance),
            'new_balance': float(wallet.balance),
            'balances': balances,
            'status': 'completed',
            'message': f'Demo deposit of {amount} {currency} completed successfully'
        }), 201

    except Exception as e:
        db.session.rollback()
        logger.error(f"Deposit simulation error: {e}", exc_info=True)
        return jsonify({'error': 'Deposit failed', 'success': False}), 500


@app.route('/api/wallet/withdraw', methods=['POST'])
@require_auth
def withdraw_eth(user_id: str):
    """Withdraw ETH to external address"""
    try:
        data = request.get_json()

        to_address = data.get('to_address')
        amount = Decimal(str(data.get('amount', 0)))

        if not to_address or amount <= 0:
            return jsonify({'error': 'Invalid withdrawal parameters'}), 400

        result = wallet_service.process_withdrawal(
            user_id=int(user_id),
            to_address=to_address,
            amount_eth=amount
        )

        return jsonify(result), 200

    except ValueError as e:
        return jsonify({'error': str(e), 'success': False}), 400
    except Exception as e:
        logger.error(f"Withdrawal error: {e}")
        return jsonify({'error': 'Withdrawal failed', 'success': False}), 500


@app.route('/api/wallet/transfer', methods=['POST'])
@require_auth
def internal_transfer(user_id: str):
    """Transfer funds to another user internally"""
    try:
        data = request.get_json()

        to_email = data.get('to_email')
        amount = Decimal(str(data.get('amount', 0)))
        currency = data.get('currency', 'ETH')
        memo = data.get('memo')

        if not to_email or amount <= 0:
            return jsonify({'error': 'Invalid transfer parameters'}), 400

        result = wallet_service.internal_transfer(
            from_user_id=int(user_id),
            to_user_email=to_email,
            amount=amount,
            currency=currency,
            memo=memo
        )

        return jsonify(result), 200

    except ValueError as e:
        return jsonify({'error': str(e), 'success': False}), 400
    except Exception as e:
        logger.error(f"Internal transfer error: {e}")
        return jsonify({'error': 'Transfer failed', 'success': False}), 500


@app.route('/api/wallet/exchange-info', methods=['GET'])
def get_exchange_wallet_info():
    """Get exchange wallet information (public)"""
    try:
        balance = wallet_service.get_balance(wallet_service.exchange_address)

        return jsonify({
            'address': wallet_service.exchange_address,
            'network': wallet_service.network,
            'balance': float(balance),
            'explorer_url': f'https://sepolia.etherscan.io/address/{wallet_service.exchange_address}'
        }), 200

    except Exception as e:
        logger.error(f"Get exchange info error: {e}")
        return jsonify({'error': str(e)}), 500


def normalize_pair(pair: str) -> str:
    """Convert ETHUSDT to ETH/USDT"""
    if '/' in pair:
        return pair

    for quote in ['USDT', 'BTC', 'ETH', 'BUSD']:
        if pair.endswith(quote):
            base = pair[:-len(quote)]
            return f"{base}/{quote}"

    return pair


def broadcast_trade_execution(trade):
    """Broadcast trade execution to all connected clients via WebSocket"""
    try:
        emit('price_update', {
            'pair': trade.pair,
            'price': float(trade.price),
            'timestamp': trade.created_at.isoformat(),
            'change': 0
        }, broadcast=True, namespace='/')

        emit('trade_update', {
            'pair': trade.pair,
            'price': float(trade.price),
            'quantity': float(trade.amount),
            'amount': float(trade.amount),
            'side': 'buy',
            'timestamp': trade.created_at.isoformat()
        }, broadcast=True, namespace='/')

        logger.info(f'Broadcasted trade execution for {trade.pair} at {trade.price}')
    except Exception as e:
        logger.error(f'Error broadcasting trade: {e}', exc_info=True)


@app.route('/api/orders/place', methods=['POST'])
@limiter.limit("100 per minute")
@require_kyc
def place_order():
    """Place trading order with database persistence and matching"""
    try:
        data = request.get_json()
        user_id = request.headers.get('X-User-ID') or data.get('user_id')

        if not user_id:
            logger.warning("Order placement attempt without user authentication")
            return jsonify({'error': 'User ID required', 'success': False}), 401

        required_fields = ['pair', 'side', 'price', 'amount']
        for field in required_fields:
            if field not in data:
                logger.warning(f"Order placement missing field: {field}")
                return jsonify({'error': f'Missing field: {field}', 'success': False}), 400

        pair = normalize_pair(data['pair'].upper())
        if not validate_trading_pair(pair.replace('/', '')):
            logger.warning(f"Invalid trading pair: {pair}")
            return jsonify({'error': 'Invalid trading pair', 'success': False}), 400

        order_side = data['side'].lower()
        price = Decimal(str(data['price']))
        amount = Decimal(str(data['amount']))

        user = User.query.get(int(user_id))
        if not user:
            return jsonify({'error': 'User not found', 'success': False}), 404

        base_currency = pair.split('/')[0] if '/' in pair else pair.replace('USDT', '')
        quote_currency = 'USDT'

        base_wallet = Wallet.query.filter_by(
            user_id=int(user_id),
            currency=base_currency
        ).first()

        quote_wallet = Wallet.query.filter_by(
            user_id=int(user_id),
            currency=quote_currency
        ).first()

        if not base_wallet or not quote_wallet:
            return jsonify({'error': 'Wallet not found', 'success': False}), 404

        try:
            if order_side == 'buy':
                # Lock USDT for buy order
                total_cost = price * amount
                quote_wallet = Wallet.query.filter_by(
                    user_id=int(user_id),
                    currency=quote_currency
                ).with_for_update().first()

                if not quote_wallet or quote_wallet.available_balance < total_cost:
                    return jsonify(
                        error=f"Insufficient {quote_currency} balance",
                        success=False
                    ), 400

                if not quote_wallet.lock_funds(total_cost):
                    return jsonify(error="Failed to lock funds", success=False), 400
            else:
                base_wallet = Wallet.query.filter_by(
                    user_id=int(user_id),
                    currency=base_currency
                ).with_for_update().first()

                if not base_wallet or base_wallet.available_balance < amount:
                    return jsonify(
                        error=f"Insufficient {base_currency} balance",
                        success=False
                    ), 400

                if not base_wallet.lock_funds(amount):
                    return jsonify(error="Failed to lock funds", success=False), 400

            db_order = Order(
                user_id=int(user_id),
                order_type=order_side,
                pair=pair.replace('/', ''),
                price=price,
                amount=amount,
                filled_amount=Decimal('0'),
                status='open',
                order_side='limit',
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc)
            )

            db.session.add(db_order)
            db.session.flush()

            logger.info(
                f"Created database order {db_order.id} for user {user_id}: {order_side} {amount} {pair} @ {price}")

            executed_trades_list = []

            if order_side == 'buy':
                matching_orders = Order.query.filter(
                    and_(
                        Order.pair == pair.replace('/', ''),
                        Order.order_type == 'sell',
                        Order.status.in_(['open', 'partially_filled']),
                        Order.price <= price,
                        Order.user_id != int(user_id)  # Can't trade with yourself
                    )
                ).order_by(Order.price.asc(), Order.created_at.asc()).all()
            else:
                matching_orders = Order.query.filter(
                    and_(
                        Order.pair == pair.replace('/', ''),
                        Order.order_type == 'buy',
                        Order.status.in_(['open', 'partially_filled']),
                        Order.price >= price,
                        Order.user_id != int(user_id)  # Can't trade with yourself
                    )
                ).order_by(Order.price.desc(), Order.created_at.asc()).all()

            remaining_amount = amount

            for maker_order in matching_orders:
                if remaining_amount <= Decimal('0.00001'):
                    break

                maker_remaining = maker_order.amount - (maker_order.filled_amount or Decimal('0'))
                trade_quantity = min(remaining_amount, maker_remaining)
                trade_price = maker_order.price  # Use maker's price

                if order_side == 'buy':
                    db_trade, success = TradeExecutor.execute_trade(
                        buy_order=db_order,
                        sell_order=maker_order,
                        quantity=trade_quantity,
                        price=trade_price
                    )
                else:
                    db_trade, success = TradeExecutor.execute_trade(
                        buy_order=maker_order,
                        sell_order=db_order,
                        quantity=trade_quantity,
                        price=trade_price
                    )

                if success and db_trade:
                    executed_trades_list.append(db_trade)
                    remaining_amount -= trade_quantity
                    logger.info(
                        f"Trade executed: {db_trade.id} - {trade_quantity} @ {trade_price} | "
                        f"Maker fee: {db_trade.maker_fee}, Taker fee: {db_trade.taker_fee}"
                    )
                    broadcast_trade_execution(db_trade)
                else:
                    logger.error(f"Failed to execute trade between orders {db_order.id} and {maker_order.id}")
                    db.session.rollback()
                    return jsonify(error="Trade execution failed", success=False), 500

            db.session.refresh(db_order)

            if db_order.filled_amount >= db_order.amount:
                db_order.status = 'filled'
                db_order.filled_at = datetime.now(timezone.utc)
            elif db_order.filled_amount > Decimal('0'):
                db_order.status = 'partially_filled'
            else:
                db_order.status = 'open'

            db_order.updated_at = datetime.now(timezone.utc)

            db.session.commit()

            base_wallet_final = Wallet.query.filter_by(
                user_id=int(user_id),
                currency=base_currency
            ).first()

            quote_wallet_final = Wallet.query.filter_by(
                user_id=int(user_id),
                currency=quote_currency
            ).first()

            orderbook = get_orderbook_from_db(pair.replace('/', ''))
            socketio.emit('orderbook_update', orderbook, namespace='/')

            socketio.emit('balance_update', {
                'user_id': user_id,
                'balances': {
                    base_currency: float(base_wallet_final.balance),
                    quote_currency: float(quote_wallet_final.balance)
                }
            }, namespace='/')

            logger.info(
                f"Order placed successfully: {db_order.id} | "
                f"Status: {db_order.status} | "
                f"Filled: {db_order.filled_amount}/{db_order.amount} | "
                f"Trades executed: {len(executed_trades_list)}"
            )

            return jsonify({
                'success': True,
                'order': {
                    'id': db_order.id,
                    'order_type': db_order.order_type,
                    'pair': db_order.pair,
                    'price': float(db_order.price),
                    'amount': float(db_order.amount),
                    'filled_amount': float(db_order.filled_amount),
                    'status': db_order.status,
                    'created_at': db_order.created_at.isoformat()
                },
                'trades_executed': len(executed_trades_list),
                'trades': [{'id': t.id, 'amount': float(t.amount), 'price': float(t.price)} for t in
                           executed_trades_list]
            }), 201

        except Exception as db_error:
            db.session.rollback()
            logger.error(f"Database error during order placement: {db_error}", exc_info=True)
            return jsonify(error="Failed to place order", success=False), 500

    except Exception as e:
        logger.error(f"Order placement error: {e}", exc_info=True)
        return jsonify(error=str(e), success=False), 500


def get_orderbook_from_db(pair: str) -> dict:
    """Get order book data directly from database"""
    try:
        from collections import defaultdict

        buy_orders = Order.query.filter(
            and_(
                Order.pair == pair,
                Order.order_type == 'buy',
                Order.status.in_(['open', 'partially_filled'])
            )
        ).order_by(Order.price.desc()).limit(50).all()

        sell_orders = Order.query.filter(
            and_(
                Order.pair == pair,
                Order.order_type == 'sell',
                Order.status.in_(['open', 'partially_filled'])
            )
        ).order_by(Order.price.asc()).limit(50).all()

        bids = defaultdict(Decimal)
        for order in buy_orders:
            remaining = order.amount - (order.filled_amount or Decimal('0'))
            if remaining > Decimal('0'):
                bids[float(order.price)] += remaining

        asks = defaultdict(Decimal)
        for order in sell_orders:
            remaining = order.amount - (order.filled_amount or Decimal('0'))
            if remaining > Decimal('0'):
                asks[float(order.price)] += remaining

        return {
            'pair': pair,
            'bids': [
                {'price': price, 'quantity': float(qty), 'total': price * float(qty)}
                for price, qty in sorted(bids.items(), reverse=True)
            ],
            'asks': [
                {'price': price, 'quantity': float(qty), 'total': price * float(qty)}
                for price, qty in sorted(asks.items())
            ],
            'success': True,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting orderbook from DB: {e}", exc_info=True)
        return {'pair': pair, 'bids': [], 'asks': [], 'success': False}


@app.route('/api/orders/<order_id>', methods=['DELETE'])
@require_auth
def cancel_order(user_id: str, order_id: str):
    """Cancel user's order"""
    try:
        order_id_int = int(order_id)
        order_obj = db.session.query(Order).filter(Order.id == order_id_int).one_or_none()
        success = matching_engine.cancel_order(order_obj.uuid, user_id)
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Order cancelled successfully'
            }), 200
        else:
            return jsonify({'error': 'Order not found or cannot be cancelled'}), 404
            
    except Exception as e:
        logger.error(f"Order cancellation error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/orders', methods=['GET'])
@require_auth
def get_user_orders(user_id: str):
    """Get user's orders"""
    try:
        orders = matching_engine.get_user_orders(user_id)
        return jsonify({
            'orders': orders,
            'total': len(orders)
        }), 200
        
    except Exception as e:
        logger.error(f"Get orders error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/orderbook/<pair>', methods=['GET'])
def get_order_book(pair: str):
    """Get order book for trading pair"""
    try:
        pair = pair.upper()
        if not validate_trading_pair(pair):
            return jsonify({'error': 'Invalid trading pair'}), 400
        
        depth = int(request.args.get('depth', 20))
        order_book = matching_engine.get_order_book(pair, depth)
        
        return jsonify(order_book), 200
        
    except Exception as e:
        logger.error(f"Order book error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/trades/<pair>', methods=['GET'])
def get_recent_trades(pair: str):
    """Get recent trades for trading pair"""
    try:
        pair = pair.upper()
        if not validate_trading_pair(pair):
            return jsonify({'error': 'Invalid trading pair'}), 400
        
        limit = int(request.args.get('limit', 50))
        trades = matching_engine.get_recent_trades(pair, limit)
        
        return jsonify({
            'pair': pair,
            'trades': trades,
            'count': len(trades)
        }), 200
        
    except Exception as e:
        logger.error(f"Recent trades error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/price/<pair>', methods=['GET'])
def get_current_price(pair: str):
    """Get current price for trading pair"""
    try:
        pair = pair.upper()
        if not validate_trading_pair(pair):
            return jsonify({'error': 'Invalid trading pair'}), 400
        
        price = price_service.get_current_price(pair)
        
        return jsonify({
            'pair': pair,
            'price': float(price),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Price fetch error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats', methods=['GET'])
def get_exchange_stats():
    """Get exchange statistics"""
    try:
        stats = matching_engine.get_stats()
        
        return jsonify({
            'stats': stats,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Stats error: {e}")
        return jsonify({'error': str(e)}), 500


@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    logger.info(f"Client connected: {request.sid}")
    emit('connection_established', {'status': 'connected'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logger.info(f"Client disconnected: {request.sid}")

@socketio.on('subscribe_orderbook')
def handle_subscribe_orderbook(data):
    """Subscribe to order book updates"""
    pair = data.get('pair', '').upper()
    if validate_trading_pair(pair):
        join_room(f"orderbook_{pair}")
        
        order_book = matching_engine.get_order_book(pair)
        emit('orderbook_update', order_book)
        
        logger.info(f"Client {request.sid} subscribed to {pair} order book")

@socketio.on('unsubscribe_orderbook')
def handle_unsubscribe_orderbook(data):
    """Unsubscribe from order book updates"""
    pair = data.get('pair', '').upper()
    if validate_trading_pair(pair):
        leave_room(f"orderbook_{pair}")
        logger.info(f"Client {request.sid} unsubscribed from {pair} order book")


@app.route('/api/wallet/info', methods=['GET'])
@require_auth
def get_wallet_info(user_id: str):
    """Get user wallet information"""
    try:
        user = User.query.get(int(user_id))
        if not user:
            return jsonify({'error': 'User not found'}), 404

        wallets = Wallet.query.filter_by(user_id=int(user_id), is_active=True).all()

        eth_wallet = EthereumWallet.query.filter_by(user_id=int(user_id), is_active=True).first()
        wallet_data = {
            'balances': {w.currency: w.to_dict() for w in wallets},
            'ethereum_address': eth_wallet.address if eth_wallet else None,
            'total_value_usd': sum(float(w.balance) for w in wallets if w.currency == 'USDT')
        }

        return jsonify(wallet_data), 200

    except Exception as e:
        logger.error(f"Get wallet info error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/wallet/transactions', methods=['GET'])
@require_auth
def get_wallet_transactions(user_id: str):
    """Get user transaction history"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        tx_type = request.args.get('type')  # Optional filter

        query = Transaction.query.filter_by(user_id=int(user_id))

        if tx_type:
            query = query.filter_by(tx_type=tx_type)

        transactions = query.order_by(Transaction.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )

        return jsonify({
            'transactions': [tx.to_dict() for tx in transactions.items],
            'total': transactions.total,
            'pages': transactions.pages,
            'current_page': page
        }), 200

    except Exception as e:
        logger.error(f"Get transactions error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/auth/change-password', methods=['POST'])
@require_auth
def change_password(user_id: str):
    """Change user password"""
    try:
        data = request.get_json()
        current_password = data.get('current_password')
        new_password = data.get('new_password')

        if not current_password or not new_password:
            return jsonify({'error': 'Current and new password required'}), 400

        user = User.query.get(int(user_id))
        if not user:
            return jsonify({'error': 'User not found'}), 404

        if not user.check_password(current_password):
            return jsonify({'error': 'Current password is incorrect'}), 401

        if len(new_password) < 8:
            return jsonify({'error': 'New password must be at least 8 characters'}), 400

        if not any(c.isupper() for c in new_password):
            return jsonify({'error': 'Password must contain at least one uppercase letter'}), 400

        if not any(c.isdigit() for c in new_password):
            return jsonify({'error': 'Password must contain at least one number'}), 400

        # Update password
        user.set_password(new_password)
        user.updated_at = datetime.now(timezone.utc)
        db.session.commit()

        logger.info(f"Password changed for user {user_id}")

        return jsonify({
            'success': True,
            'message': 'Password changed successfully'
        }), 200

    except Exception as e:
        db.session.rollback()
        logger.error(f"Change password error: {e}")
        return jsonify({'error': 'Failed to change password'}), 50


@app.route('/api/market/price/<pair>', methods=['GET'])
def get_market_price(pair: str):
    """Get current market price for a trading pair"""
    try:
        pair = pair.upper()
        if not validate_trading_pair(pair):
            return jsonify({'error': 'Invalid trading pair', 'success': False}), 400

        price = price_service.get_current_price(pair)

        stats = {
            'success': True,
            'pair': pair,
            'price': float(price),
            'change': 0.0,  # Calculate from historical data
            'timestamp': datetime.now(timezone.utc).isoformat()
        }

        return jsonify(stats), 200

    except Exception as e:
        logger.error(f"Get market price error: {e}")
        return jsonify({'error': str(e), 'success': False}), 500


@app.route('/api/market/orderbook/<pair>', methods=['GET'])
def get_market_orderbook(pair: str):
    """Get order book for a trading pair - from database"""
    try:
        pair = pair.upper()
        if not validate_trading_pair(pair):
            return jsonify(error="Invalid trading pair"), 400

        from collections import defaultdict
        from sqlalchemy import and_

        buy_orders = Order.query.filter(
            and_(
                Order.pair == pair,
                Order.order_type == 'buy',
                Order.status.in_(['open', 'partially_filled'])
            )
        ).order_by(Order.price.desc()).limit(50).all()

        sell_orders = Order.query.filter(
            and_(
                Order.pair == pair,
                Order.order_type == 'sell',
                Order.status.in_(['open', 'partially_filled'])
            )
        ).order_by(Order.price.asc()).limit(50).all()

        bids = defaultdict(Decimal)
        for order in buy_orders:
            remaining = order.amount - (order.filled_amount or Decimal('0'))
            if remaining > Decimal('0'):
                bids[float(order.price)] += remaining

        asks = defaultdict(Decimal)
        for order in sell_orders:
            remaining = order.amount - (order.filled_amount or Decimal('0'))
            if remaining > Decimal('0'):
                asks[float(order.price)] += remaining

        orderbook = {
            'pair': pair,
            'bids': [
                {
                    'price': float(price),
                    'quantity': float(qty),
                    'total': float(Decimal(str(price)) * qty)
                }
                for price, qty in sorted(bids.items(), reverse=True)
            ],
            'asks': [
                {
                    'price': float(price),
                    'quantity': float(qty),
                    'total': float(Decimal(str(price)) * qty)
                }
                for price, qty in sorted(asks.items())
            ],
            'success': True,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }

        return jsonify(orderbook), 200

    except Exception as e:
        logger.error(f"Get market orderbook error: {e}", exc_info=True)
        return jsonify(error=str(e), success=False), 500


@app.route('/api/market/trades/<pair>', methods=['GET'])
def get_market_trades(pair: str):
    """Get recent trades for a trading pair"""
    try:
        pair_clean = pair.upper().replace('/', '')
        if not validate_trading_pair(pair_clean):
            return jsonify({'error': 'Invalid trading pair', 'success': False}), 400

        limit = int(request.args.get('limit', 50))

        db_trades = Trade.query.filter_by(pair=pair_clean).order_by(
            Trade.created_at.asc()
        ).limit(limit).all()

        trades_list = []
        for trade in db_trades:
            trades_list.append({
                'id': trade.id,
                'price': float(trade.price),
                'quantity': float(trade.amount),
                'amount': float(trade.amount),
                'side': 'buy',
                'timestamp': trade.created_at.isoformat()
            })

        return jsonify({
            'success': True,
            'pair': pair_clean,
            'trades': trades_list,
            'count': len(trades_list)
        }), 200

    except Exception as e:
        logger.error(f"Get market trades error: {e}")
        return jsonify({'error': str(e), 'success': False}), 500


@app.route('/api/market/history/<pair>', methods=['GET'])
def get_market_history(pair: str):
    """Get historical price data for chart from database"""
    try:
        pair = pair.upper()
        if not validate_trading_pair(pair):
            return jsonify(error='Invalid trading pair', success=False), 400

        hours = int(request.args.get('hours', 24))
        limit = int(request.args.get('limit', 100))

        start_time = datetime.now(timezone.utc) - timedelta(hours=hours)

        trades = Trade.query.filter(
            and_(
                Trade.pair == pair,
                Trade.created_at >= start_time
            )
        ).order_by(Trade.created_at.asc()).limit(limit).all()

        chart_data = []
        for trade in trades:
            chart_data.append({
                'timestamp': trade.created_at.isoformat(),
                'price': float(trade.price),
                'amount': float(trade.amount),
                'value': float(trade.trade_value)
            })

        if not chart_data:
            try:
                current_price = price_service.get_current_price(pair)
                chart_data.append({
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'price': float(current_price),
                    'amount': 0,
                    'value': 0
                })
            except:
                pass

        return jsonify({
            'success': True,
            'pair': pair,
            'data': chart_data,
            'count': len(chart_data),
            'start_time': start_time.isoformat(),
            'end_time': datetime.now(timezone.utc).isoformat()
        }), 200

    except Exception as e:
        logger.error(f'Get market history error: {e}', exc_info=True)
        return jsonify(error=str(e), success=False), 500


@app.route('/api/wallet/balances', methods=['GET'])
@require_auth
def get_wallet_balances(user_id: str):
    """Get all wallet balances for authenticated user"""
    try:
        wallets = Wallet.query.filter_by(user_id=int(user_id), is_active=True).all()

        balances = {}
        total_value_usd = 0

        for wallet in wallets:
            balances[wallet.currency] = {
                'balance': float(wallet.balance),
                'available': float(wallet.available_balance),
                'locked': float(wallet.locked_balance)
            }

            if wallet.currency == 'USDT':
                total_value_usd += float(wallet.balance)

        return jsonify({
            'success': True,
            'balances': balances,
            'total_value_usd': total_value_usd
        }), 200

    except Exception as e:
        logger.error(f"Get wallet balances error: {e}")
        return jsonify({'error': str(e), 'success': False}), 500


@app.route('/api/wallet/deposit-address', methods=['GET'])
@require_auth
def get_deposit_address(user_id: str):
    """Get or create deposit address for user"""
    try:
        result = wallet_service.create_user_deposit_address(int(user_id))

        return jsonify({
            'success': True,
            **result
        }), 200

    except Exception as e:
        logger.error(f"Get deposit address error: {e}")
        return jsonify({'error': str(e), 'success': False}), 500


@app.route('/api/wallet/check-deposit', methods=['POST'])
@require_auth
def manual_check_deposit(user_id: str):
    """Manually trigger deposit check"""
    try:
        eth_wallet = EthereumWallet.query.filter_by(
            user_id=int(user_id),
            is_active=True
        ).first()

        if not eth_wallet:
            return jsonify({'error': 'No deposit address found'}), 404

        result = wallet_service.check_deposit(
            user_id=int(user_id),
            address=eth_wallet.address
        )

        if not result:
            return jsonify({
                'success': True,
                'message': 'No pending deposits found',
                'balance': float(wallet_service.get_balance(eth_wallet.address))
            }), 200

        return jsonify({
            'success': True,
            **result
        }), 200

    except Exception as e:
        logger.error(f"Check deposit error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/orders/history', methods=['GET'])
@require_auth
def get_order_history(user_id: str):
    """Get user's order history from database"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)

        orders_query = Order.query.filter_by(user_id=int(user_id)).order_by(
            Order.created_at.desc()
        )

        orders_paginated = orders_query.paginate(page=page, per_page=per_page, error_out=False)

        return jsonify({
            'success': True,
            'orders': [order.to_dict() for order in orders_paginated.items],
            'total': orders_paginated.total,
            'pages': orders_paginated.pages,
            'current_page': page
        }), 200

    except Exception as e:
        logger.error(f"Get order history error: {e}")
        return jsonify({'error': str(e), 'success': False}), 500


@app.route('/api/trades/history', methods=['GET'])
@require_auth
def get_trade_history(user_id: str):
    """Get user's trade history from database"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)

        trades_query = Trade.query.filter(
            (Trade.maker_user_id == int(user_id)) | (Trade.taker_user_id == int(user_id))
        ).order_by(Trade.created_at.desc())

        trades_paginated = trades_query.paginate(page=page, per_page=per_page, error_out=False)

        return jsonify({
            'success': True,
            'trades': [trade.to_dict() for trade in trades_paginated.items],
            'total': trades_paginated.total,
            'pages': trades_paginated.pages,
            'current_page': page
        }), 200

    except Exception as e:
        logger.error(f"Get trade history error: {e}")
        return jsonify({'error': str(e), 'success': False}), 500


def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def validate_file(file):
    """Validate uploaded file"""
    if not file or file.filename == '':
        return False, "No file selected"

    if not allowed_file(file.filename):
        return False, f"File type not allowed. Allowed: {', '.join(ALLOWED_EXTENSIONS)}"

    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)

    if size > MAX_FILE_SIZE:
        return False, f"File too large. Max size: {MAX_FILE_SIZE // (1024 * 1024)}MB"

    return True, "Valid"


@app.route('/api/kyc/submit', methods=['POST'])
@require_auth
def submit_kyc(user_id: str):
    """Submit KYC documents with proper file handling"""
    try:
        existing_kyc = KYC.query.filter_by(
            user_id=int(user_id),
            status='pending'
        ).first()

        if existing_kyc:
            return jsonify({
                'success': False,
                'error': 'KYC submission already pending'
            }), 400

        fullname = request.form.get('fullname', '').strip()
        dateofbirth = request.form.get('dateofbirth', '').strip()
        country = request.form.get('country', '').strip()
        address = request.form.get('address', '').strip()
        phone = request.form.get('phone', '').strip()
        idtype = request.form.get('idtype', '').strip()
        idnumber = request.form.get('idnumber', '').strip()

        if not all([fullname, dateofbirth, country, idtype]):
            return jsonify({
                'success': False,
                'error': 'Missing required fields'
            }), 400

        upload_folder = os.path.join('uploads', 'kyc', str(user_id))
        os.makedirs(upload_folder, exist_ok=True)

        file_fields = ['id_front', 'id_back', 'selfie', 'proof_of_address']
        file_paths = {}
        uploaded_files = []

        for field in file_fields:
            if field in request.files:
                file = request.files[field]

                is_valid, message = validate_file(file)
                if not is_valid:
                    for uploaded in uploaded_files:
                        try:
                            os.remove(uploaded)
                        except:
                            pass
                    return jsonify({
                        'success': False,
                        'error': f'{field}: {message}'
                    }), 400

                if file and file.filename:
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    ext = file.filename.rsplit('.', 1)[1].lower()
                    filename = secure_filename(f"{user_id}_{field}_{timestamp}.{ext}")
                    filepath = os.path.join(upload_folder, filename)

                    file.save(filepath)
                    file_paths[f'{field}_path'] = filepath
                    uploaded_files.append(filepath)

        required_files = ['id_front_path', 'id_back_path', 'selfie_path']
        if not all(k in file_paths for k in required_files):
            for uploaded in uploaded_files:
                try:
                    os.remove(uploaded)
                except:
                    pass
            return jsonify({
                'success': False,
                'error': 'ID front, ID back, and selfie are required'
            }), 400

        from datetime import date
        try:
            # Handle DD-MM-YYYY format
            day, month, year = dateofbirth.split('-')
            dob = date(int(year), int(month), int(day))
        except:
            return jsonify({
                'success': False,
                'error': 'Invalid date format. Use DD-MM-YYYY'
            }), 400

        kyc = KYC(
            user_id=int(user_id),
            full_name=fullname,
            date_of_birth=dob,
            country=country,
            address=address,
            phone=phone,
            id_type=idtype,
            id_number=idnumber,
            **file_paths,
            status='pending',
            submitted_at=datetime.now(timezone.utc)
        )

        db.session.add(kyc)

        user = User.query.get(int(user_id))
        user.kyc_status = 'pending'
        user.kyc_submitted_at = datetime.now(timezone.utc)

        db.session.commit()

        logger.info(f"KYC submitted for user {user_id}")

        return jsonify({
            'success': True,
            'message': 'KYC documents submitted successfully',
            'kyc_id': kyc.id,
            'status': 'pending'
        }), 201

    except Exception as e:
        db.session.rollback()
        if 'uploaded_files' in locals():
            for uploaded in uploaded_files:
                try:
                    os.remove(uploaded)
                except:
                    pass
        logger.error(f"KYC submission error: {e}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'Failed to submit KYC'
        }), 500


@app.route('/kyc', methods=['GET', 'POST'])
def kyc_page():
    """KYC submission page"""
    if request.method == 'GET':
        return render_template('kyc.html')

    return redirect(url_for('submit_kyc'))


@app.route('/api/auth/logout', methods=['POST'])
def logout():
    """Logout user"""
    try:
        from flask_login import logout_user
        logout_user()
        session.clear()

        return jsonify({
            'success': True,
            'message': 'Logged out successfully'
        }), 200

    except Exception as e:
        logger.error(f"Logout error: {e}")
        return jsonify({'error': 'Logout failed'}), 500



@app.route('/')
def index():
    """Main trading interface"""
    return render_template('index.html')

@app.route('/trading')
def trading_page():
    """Advanced trading page"""
    return render_template('trading.html')


@app.route('/wallet')
def wallet_page():
    """Wallet management page"""
    if not current_user.is_authenticated:
        return redirect(url_for('login'))

    return render_template('wallet.html', user=current_user)


@app.route('/profile')
def profile_page():
    """User profile page"""
    if not current_user.is_authenticated:
        return redirect(url_for('login'))

    return render_template('profile.html', user=current_user)


@app.route('/api/kyc/status', methods=['GET'])
@require_auth
def get_kyc_status(user_id: str):
    """Get user's KYC status"""
    try:
        user = User.query.get(int(user_id))
        kyc = KYC.query.filter_by(user_id=int(user_id)).order_by(
            KYC.submitted_at.desc()
        ).first()

        return jsonify({
            'success': True,
            'kyc_status': user.kyc_status,
            'kyc_verified_at': user.kyc_verified_at.isoformat() if user.kyc_verified_at else None,
            'kyc_details': kyc.to_dict() if kyc else None
        }), 200

    except Exception as e:
        logger.error(f"Get KYC status error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/kyc/pending', methods=['GET'])
@require_auth
def get_pending_kyc(user_id: str):
    """Admin: Get all pending KYC submissions"""
    try:
        user = User.query.get(int(user_id))
        if not user or not user.is_admin:
            return jsonify({'error': 'Admin access required'}), 403

        pending_kycs = KYC.query.filter_by(status='pending').order_by(
            KYC.submitted_at.asc()
        ).all()

        return jsonify({
            'success': True,
            'pending_kycs': [kyc.to_dict() for kyc in pending_kycs],
            'count': len(pending_kycs)
        }), 200

    except Exception as e:
        logger.error(f"Get pending KYC error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/uploads/kyc/<path:filename>')
def serve_kyc_file(filename):
    return send_from_directory('uploads/kyc/', filename)


@app.route('/api/admin/kyc/review', methods=['POST'])
@require_auth
def review_kyc(user_id: str):
    """Admin: Approve or reject KYC submission"""
    try:
        admin = User.query.get(int(user_id))
        if not admin or not admin.is_admin:
            return jsonify({'error': 'Admin access required'}), 403

        data = request.get_json()
        kyc_id = data.get('kyc_id')
        action = data.get('action')
        rejection_reason = data.get('rejection_reason')

        if not kyc_id or action not in ['approve', 'reject']:
            return jsonify({'error': 'Invalid parameters'}), 400

        kyc = KYC.query.get(kyc_id)
        if not kyc:
            return jsonify({'error': 'KYC record not found'}), 404

        if kyc.status != 'pending':
            return jsonify({'error': 'KYC already reviewed'}), 400

        kyc.reviewed_by = int(user_id)
        kyc.reviewed_at = datetime.now(timezone.utc)

        if action == 'approve':
            kyc.status = 'approved'
            kyc.approved_at = datetime.now(timezone.utc)
            kyc.verification_level = 'basic'

            user = User.query.get(kyc.user_id)
            user.kyc_status = 'approved'
            user.kyc_verified_at = datetime.now(timezone.utc)
            user.is_verified = True

            message = f"KYC approved for user {user.username}"

        else:
            kyc.status = 'rejected'
            kyc.rejection_reason = rejection_reason or 'Documents do not meet requirements'

            user = User.query.get(kyc.user_id)
            user.kyc_status = 'rejected'

            message = f"KYC rejected for user {user.username}"

        db.session.commit()

        logger.info(f"KYC reviewed: {message} by admin {admin.username}")

        return jsonify({
            'success': True,
            'message': message,
            'kyc': kyc.to_dict()
        }), 200

    except Exception as e:
        db.session.rollback()
        logger.error(f"KYC review error: {e}", exc_info=True)
        return jsonify({'error': 'Failed to review KYC'}), 500


@app.route('/api/portfolio/summary', methods=['GET'])
@require_auth
def get_portfolio_summary(user_id: str):
    """Get comprehensive portfolio summary with USD values"""
    try:
        wallets = Wallet.query.filter_by(
            user_id=int(user_id),
            is_active=True
        ).all()

        portfolio = []
        total_value_usd = Decimal('0')

        for wallet in wallets:
            if wallet.balance > 0:
                try:
                    if wallet.currency == 'USDT':
                        price_usd = Decimal('1.0')
                    else:
                        price = price_service.get_current_price(f"{wallet.currency}USDT")
                        price_usd = Decimal(str(price))
                except:
                    price_usd = Decimal('0')

                value_usd = wallet.balance * price_usd
                total_value_usd += value_usd

                portfolio.append({
                    'currency': wallet.currency,
                    'balance': float(wallet.balance),
                    'available': float(wallet.available_balance),
                    'locked': float(wallet.locked_balance),
                    'price_usd': float(price_usd),
                    'value_usd': float(value_usd)
                })

        recent_trades = Trade.query.filter(
            (Trade.maker_user_id == int(user_id)) | (Trade.taker_user_id == int(user_id))
        ).order_by(Trade.created_at.desc()).limit(10).all()

        trades_list = []
        for trade in recent_trades:
            side = 'buy' if trade.taker_user_id == int(user_id) else 'sell'
            trades_list.append({
                'id': trade.id,
                'pair': trade.pair,
                'side': side,
                'price': float(trade.price),
                'amount': float(trade.amount),
                'total': float(trade.trade_value),
                'fee': float(trade.maker_fee if trade.maker_user_id == int(user_id) else trade.taker_fee),
                'timestamp': trade.created_at.isoformat()
            })

        open_orders = Order.query.filter_by(
            user_id=int(user_id)
        ).filter(
            Order.status.in_(['open', 'partially_filled'])
        ).order_by(Order.created_at.desc()).all()

        orders_list = []
        for order in open_orders:
            orders_list.append({
                'id': order.id,
                'pair': order.pair,
                'side': order.order_type,
                'price': float(order.price),
                'amount': float(order.amount),
                'filled': float(order.filled_amount or 0),
                'remaining': float(order.remaining_amount),
                'status': order.status,
                'total': float(order.price * order.amount),
                'created_at': order.created_at.isoformat()
            })

        return jsonify({
            'success': True,
            'portfolio': {
                'assets': portfolio,
                'total_value_usd': float(total_value_usd)
            },
            'recent_trades': trades_list,
            'open_orders': orders_list
        }), 200

    except Exception as e:
        logger.error(f"Portfolio summary error: {e}", exc_info=True)
        return jsonify({'error': str(e), 'success': False}), 500


@app.route('/admin/kyc')
def admin_kyc_review():
    """Admin KYC review page"""
    if not current_user.is_authenticated or not current_user.is_admin:
        return redirect(url_for('login'))

    return render_template('admin_kyc_review.html')


def start_background_tasks(app):
    start_deposit_monitor(app)
    logger.info("Background tasks started")


@app.teardown_appcontext
def shutdown_session(exception=None):
    """Remove database session on application teardown"""
    db.session.remove()


if __name__ == '__main__':
    # Start background tasks
    start_background_tasks(app)

    # Run the application
    port = int(os.getenv('PORT', 5003))
    debug = os.getenv('FLASK_ENV') == 'development'

    logger.info(f"Starting Crypto Exchange on port {port}")
    logger.info(f"Database: {app.config['SQLALCHEMY_DATABASE_URI']}")
    logger.info(f"Redis: {app.config['REDIS_URL']}")

    socketio.run(
        app,
        host='0.0.0.0',
        port=5003,
        debug=debug,
        allow_unsafe_werkzeug=True
    )
