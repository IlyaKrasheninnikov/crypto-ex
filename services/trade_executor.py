from decimal import Decimal
from typing import List, Tuple
from models import db, Order, Trade, Wallet, User, PlatformWallet
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)


class TradeExecutor:
    @staticmethod
    def parse_pair(pair: str) -> Tuple[str, str]:
        if '/' in pair:
            return tuple(pair.split('/'))
        quote_currencies = ['USDT', 'USDC', 'BTC', 'ETH', 'BNB', 'BUSD']
        for quote in quote_currencies:
            if pair.endswith(quote):
                base = pair[:-len(quote)]
                return base, quote

        raise ValueError(f"Cannot parse trading pair: {pair}")

    @staticmethod
    def execute_trade(buy_order: Order, sell_order: Order,
                      quantity: Decimal, price: Decimal) -> Tuple[Trade, bool]:
        try:
            db.session.begin_nested()
            base_currency, quote_currency = TradeExecutor.parse_pair(buy_order.pair)
            trade_value = quantity * price

            logger.info(f"Executing trade: {quantity} {base_currency} @ {price} {quote_currency}")

            buyer_quote_wallet = Wallet.query.filter_by(
                user_id=buy_order.user_id,
                currency=quote_currency
            ).with_for_update().first()

            buyer_base_wallet = Wallet.query.filter_by(
                user_id=buy_order.user_id,
                currency=base_currency
            ).with_for_update().first()

            seller_base_wallet = Wallet.query.filter_by(
                user_id=sell_order.user_id,
                currency=base_currency
            ).with_for_update().first()

            seller_quote_wallet = Wallet.query.filter_by(
                user_id=sell_order.user_id,
                currency=quote_currency
            ).with_for_update().first()

            if not all([buyer_quote_wallet, buyer_base_wallet,
                        seller_base_wallet, seller_quote_wallet]):
                missing = []
                if not buyer_quote_wallet:
                    missing.append(f"buyer {quote_currency}")
                if not buyer_base_wallet:
                    missing.append(f"buyer {base_currency}")
                if not seller_base_wallet:
                    missing.append(f"seller {base_currency}")
                if not seller_quote_wallet:
                    missing.append(f"seller {quote_currency}")

                db.session.rollback()
                logger.error(f"Missing wallets for trade execution: {', '.join(missing)}")
                return None, False

            from services.fee_service import FeeService
            fee_service = FeeService()

            buyer_user = User.query.get(buy_order.user_id)
            seller_user = User.query.get(sell_order.user_id)

            maker_fee = fee_service.calculate_fee(
                trade_value,
                seller_user.vip_tier,
                is_maker=True
            )

            taker_fee = fee_service.calculate_fee(
                trade_value,
                buyer_user.vip_tier,
                is_maker=False
            )

            for currency in [base_currency, quote_currency]:
                platform_wallet = PlatformWallet.query.filter_by(
                    currency=currency
                ).with_for_update().first()

                if not platform_wallet:
                    platform_wallet = PlatformWallet(currency=currency)
                    db.session.add(platform_wallet)
                    db.session.flush()

                if currency == base_currency:
                    platform_wallet.add_revenue(maker_fee + taker_fee, 'trading_fee')

                db.session.add(platform_wallet)

            logger.info(f"Fees calculated - Maker: {maker_fee} {quote_currency}, Taker: {taker_fee} {quote_currency}")

            amount_locked_for_this_trade = quantity * buy_order.price

            buyer_quote_wallet.unlock_funds(amount_locked_for_this_trade)

            actual_payment = trade_value + taker_fee
            buyer_quote_wallet.balance -= actual_payment

            buyer_base_wallet.balance += quantity

            seller_base_wallet.unlock_funds(quantity)
            seller_base_wallet.balance -= quantity
            seller_quote_wallet.balance += (trade_value - maker_fee)

            logger.info(
                f"Balances updated - "
                f"Buyer: -{trade_value + taker_fee} {quote_currency}, +{quantity} {base_currency} | "
                f"Seller: -{quantity} {base_currency}, +{trade_value - maker_fee} {quote_currency}"
            )

            buy_order.filled_amount = (buy_order.filled_amount or Decimal('0')) + quantity
            sell_order.filled_amount = (sell_order.filled_amount or Decimal('0')) + quantity

            if buy_order.filled_amount >= buy_order.amount:
                buy_order.status = 'filled'
                buy_order.filled_at = datetime.now(timezone.utc)
            else:
                buy_order.status = 'partially_filled'

            if sell_order.filled_amount >= sell_order.amount:
                sell_order.status = 'filled'
                sell_order.filled_at = datetime.now(timezone.utc)
            else:
                sell_order.status = 'partially_filled'

            buy_order.updated_at = datetime.now(timezone.utc)
            sell_order.updated_at = datetime.now(timezone.utc)

            buy_order.fee_paid = (buy_order.fee_paid or Decimal('0')) + taker_fee
            buy_order.fee_currency = quote_currency
            buy_order.taker_fee_rate = fee_service.vip_tiers[buyer_user.vip_tier]['taker_fee']

            sell_order.fee_paid = (sell_order.fee_paid or Decimal('0')) + maker_fee
            sell_order.fee_currency = quote_currency
            sell_order.maker_fee_rate = fee_service.vip_tiers[seller_user.vip_tier]['maker_fee']

            trade = Trade(
                maker_order_id=sell_order.id,
                taker_order_id=buy_order.id,
                maker_user_id=sell_order.user_id,
                taker_user_id=buy_order.user_id,
                pair=buy_order.pair,
                price=price,
                amount=quantity,
                trade_value=trade_value,
                maker_fee=maker_fee,
                taker_fee=taker_fee,
                total_fee=maker_fee + taker_fee,
                created_at=datetime.now(timezone.utc)
            )

            db.session.add(trade)
            db.session.commit()

            logger.info(
                f"Trade executed successfully: {quantity} {base_currency} @ {price} {quote_currency} | "
                f"Total fees collected: {maker_fee + taker_fee} {quote_currency}"
            )

            return trade, True

        except Exception as e:
            db.session.rollback()
            logger.error(f"Trade execution failed: {e}", exc_info=True)
            return None, False
