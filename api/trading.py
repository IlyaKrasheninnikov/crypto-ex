import logging
from datetime import timezone
from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from models import db, Order, Wallet, Trade
from services.matching_engine import MatchingEngine
from decimal import Decimal
from sqlalchemy import and_, desc

logger = logging.getLogger(__name__)
trading_bp = Blueprint('trading', __name__, url_prefix='/api/trading')


def get_matching_engine():
    from flask import current_app
    return MatchingEngine(current_app.config)


@trading_bp.route('/orderbook/<pair>', methods=['GET'])
def get_orderbook(pair):
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

        return jsonify({
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
            'success': True
        }), 200

    except Exception as e:
        logger.error(f"Error fetching order book: {e}", exc_info=True)
        return jsonify({
            'error': str(e),
            'success': False
        }), 500


@trading_bp.route('/order', methods=['POST'])
@login_required
def create_order():
    try:
        data = request.json

        order_type = data.get('type')
        pair = data.get('pair')
        price = Decimal(str(data.get('price')))
        amount = Decimal(str(data.get('amount')))

        if order_type not in ['buy', 'sell']:
            return jsonify({'error': 'Invalid order type'}), 400

        if price <= 0 or amount <= 0:
            return jsonify({'error': 'Invalid price or amount'}), 400

        base_currency, quote_currency = pair.split('/')

        db.session.begin_nested()

        try:
            if order_type == 'buy':
                required_amount = price * amount
                wallet = Wallet.query.filter_by(
                    user_id=current_user.id,
                    currency=quote_currency
                ).with_for_update().first()

                if not wallet or wallet.available_balance < required_amount:
                    db.session.rollback()
                    return jsonify({'error': 'Insufficient balance'}), 400

                if not wallet.lock_funds(required_amount):
                    db.session.rollback()
                    return jsonify({'error': 'Failed to lock funds'}), 500
            else:
                wallet = Wallet.query.filter_by(
                    user_id=current_user.id,
                    currency=base_currency
                ).with_for_update().first()

                if not wallet or wallet.available_balance < amount:
                    db.session.rollback()
                    return jsonify({'error': 'Insufficient balance'}), 400

                if not wallet.lock_funds(amount):
                    db.session.rollback()
                    return jsonify({'error': 'Failed to lock funds'}), 500

            order = Order(
                user_id=current_user.id,
                order_type=order_type,
                pair=pair,
                price=price,
                amount=amount
            )
            db.session.add(order)
            db.session.commit()

            # Match order
            matching_engine = get_matching_engine()
            trades = matching_engine.match_order(order)

            return jsonify({
                'order': order.to_dict(),
                'trades': [t.to_dict() for t in trades]
            }), 201

        except Exception as e:
            db.session.rollback()
            raise

    except ValueError as e:
        return jsonify({'error': 'Invalid input format'}), 400
    except Exception as e:
        logger.error(f"Order creation error: {e}")
        return jsonify({'error': str(e)}), 500


@trading_bp.route('/order/<int:order_id>/cancel', methods=['POST'])
@login_required
def cancel_order(order_id):
    try:
        order = Order.query.get_or_404(order_id)

        if order.user_id != current_user.id:
            return jsonify({'error': 'Unauthorized'}), 403

        matching_engine = get_matching_engine()
        success, message = matching_engine.cancel_order(order)

        if success:
            return jsonify({
                'message': message,
                'order': order.to_dict()
            })
        else:
            return jsonify({'error': message}), 400

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@trading_bp.route('/orders', methods=['GET'])
@login_required
def get_orders():
    try:
        status = request.args.get('status', 'all')
        pair = request.args.get('pair')
        limit = int(request.args.get('limit', 50))

        query = Order.query.filter_by(user_id=current_user.id)

        if status != 'all':
            query = query.filter_by(status=status)

        if pair:
            query = query.filter_by(pair=pair)

        orders = query.order_by(desc(Order.created_at)).limit(limit).all()

        return jsonify({
            'orders': [order.to_dict() for order in orders]
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@trading_bp.route('/trades', methods=['GET'])
@login_required
def get_trades():
    try:
        pair = request.args.get('pair')
        limit = int(request.args.get('limit', 50))

        query = Trade.query.filter(
            (Trade.maker_user_id == current_user.id) |
            (Trade.taker_user_id == current_user.id)
        )

        if pair:
            query = query.filter_by(pair=pair)

        trades = query.order_by(desc(Trade.created_at)).limit(limit).all()

        return jsonify({
            'trades': [trade.to_dict() for trade in trades]
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@trading_bp.route('/market/<pair>', methods=['GET'])
def get_market_data(pair):
    try:
        from datetime import datetime, timedelta

        since = datetime.now(timezone.utc) - timedelta(hours=24)
        trades = Trade.query.filter(
            and_(
                Trade.pair == pair,
                Trade.created_at >= since
            )
        ).all()

        if not trades:
            return jsonify({
                'pair': pair,
                'last_price': 0,
                'volume': 0,
                'high': 0,
                'low': 0,
                'change_24h': 0
            })

        prices = [float(t.price) for t in trades]
        volumes = [float(t.amount) for t in trades]

        return jsonify({
            'pair': pair,
            'last_price': prices[-1],
            'volume': sum(volumes),
            'high': max(prices),
            'low': min(prices),
            'change_24h': ((prices[-1] - prices[0]) / prices[0] * 100) if prices[0] > 0 else 0
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500
