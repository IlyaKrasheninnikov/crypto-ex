from enum import Enum
from decimal import Decimal, ROUND_DOWN
from typing import List, Dict, Optional, Tuple, Any
from datetime import datetime, timezone
from dataclasses import dataclass, field
import heapq
import logging
import uuid
import time
from collections import defaultdict

logger = logging.getLogger(__name__)

class OrderType(Enum):
    BUY = "buy"
    SELL = "sell"
    MARKET_BUY = "market_buy"
    MARKET_SELL = "market_sell"

class OrderStatus(Enum):
    PENDING = "pending"
    PARTIALLY_FILLED = "partially_filled"
    FILLED = "filled"
    CANCELLED = "cancelled"
    REJECTED = "rejected"

@dataclass(order=True)
class Order:
    timestamp: float = field(compare=True)
    order_id: str = field(compare=False)
    user_id: str = field(compare=False)
    pair: str = field(compare=False)
    order_type: OrderType = field(compare=False)
    price: Decimal = field(compare=False)
    quantity: Decimal = field(compare=False)
    filled_quantity: Decimal = field(default=Decimal('0'), compare=False)
    status: OrderStatus = field(default=OrderStatus.PENDING, compare=False)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc), compare=False)
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc), compare=False)

    def __post_init__(self):
        self.price = Decimal(str(self.price)).quantize(Decimal('0.01'), rounding=ROUND_DOWN)
        self.quantity = Decimal(str(self.quantity)).quantize(Decimal('0.00001'), rounding=ROUND_DOWN)
        self.filled_quantity = Decimal(str(self.filled_quantity)).quantize(Decimal('0.00001'), rounding=ROUND_DOWN)

    @property
    def id(self):
        return self.order_id

    def remaining_quantity(self) -> Decimal:
        return self.quantity - self.filled_quantity

    def is_filled(self) -> bool:
        return self.remaining_quantity() <= Decimal('0.00001')

    def fill(self, quantity: Decimal) -> None:
        fill_amount = min(quantity, self.remaining_quantity())
        self.filled_quantity += fill_amount
        self.updated_at = datetime.now(timezone.utc)

        if self.is_filled():
            self.status = OrderStatus.FILLED
        elif self.filled_quantity > Decimal('0'):
            self.status = OrderStatus.PARTIALLY_FILLED

    def to_dict(self) -> Dict:
        return {
            'id': self.order_id,
            'order_id': self.order_id,
            'user_id': self.user_id,
            'pair': self.pair,
            'order_type': self.order_type.value,
            'price': float(self.price),
            'quantity': float(self.quantity),
            'filled_quantity': float(self.filled_quantity),
            'remaining_quantity': float(self.remaining_quantity()),
            'status': self.status.value,
            'timestamp': self.timestamp,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }

@dataclass
class Trade:
    trade_id: str
    pair: str
    price: Decimal
    quantity: Decimal
    buyer_id: str
    seller_id: str
    buyer_order_id: str
    seller_order_id: str
    timestamp: datetime

    def to_dict(self) -> Dict:
        return {
            'trade_id': self.trade_id,
            'pair': self.pair,
            'price': float(self.price),
            'quantity': float(self.quantity),
            'buyer_id': self.buyer_id,
            'seller_id': self.seller_id,
            'buyer_order_id': self.buyer_order_id,
            'seller_order_id': self.seller_order_id,
            'timestamp': self.timestamp.isoformat(),
            'value': float(self.price * self.quantity)
        }

class OrderBook:

    def __init__(self, pair: str):
        self.pair = pair
        self.buy_orders = []
        self.sell_orders = []
        self.order_map = {}
        self.price_levels_buy = defaultdict(list)
        self.price_levels_sell = defaultdict(list)

    def add_order(self, order: Order) -> None:
        self.order_map[order.order_id] = order

        if order.order_type == OrderType.BUY:
            heapq.heappush(self.buy_orders, (-float(order.price), order.timestamp, order.order_id))
            self.price_levels_buy[order.price].append(order.order_id)
        else:
            heapq.heappush(self.sell_orders, (float(order.price), order.timestamp, order.order_id))
            self.price_levels_sell[order.price].append(order.order_id)

        logger.debug(f"Added {order.order_type.value} order {order.order_id} at price {order.price}")

    def get_best_buy_order(self) -> Optional[Order]:
        while self.buy_orders:
            neg_price, timestamp, order_id = self.buy_orders[0]
            order = self.order_map.get(order_id)

            if order and not order.is_filled() and order.status != OrderStatus.CANCELLED:
                return order
            else:
                heapq.heappop(self.buy_orders)
                if order:
                    self._remove_from_price_level(order.price, order_id, True)

        return None

    def get_best_sell_order(self) -> Optional[Order]:
        while self.sell_orders:
            price, timestamp, order_id = self.sell_orders[0]
            order = self.order_map.get(order_id)

            if order and not order.is_filled() and order.status != OrderStatus.CANCELLED:
                return order
            else:
                heapq.heappop(self.sell_orders)
                if order:
                    self._remove_from_price_level(order.price, order_id, False)

        return None

    def _remove_from_price_level(self, price: Decimal, order_id: str, is_buy: bool):
        try:
            price_levels = self.price_levels_buy if is_buy else self.price_levels_sell

            if price in price_levels and order_id in price_levels[price]:
                price_levels[price].remove(order_id)

                if not price_levels[price]:
                    del price_levels[price]
        except Exception as e:
            logger.error(f"Error removing order {order_id} from price level {price}: {e}")

    def cancel_order(self, order_id: str) -> bool:
        if order_id in self.order_map:
            order = self.order_map[order_id]
            order.status = OrderStatus.CANCELLED
            order.updated_at = datetime.now(timezone.utc)

            is_buy = order.order_type == OrderType.BUY
            self._remove_from_price_level(order.price, order_id, is_buy)

            del self.order_map[order_id]

            logger.info(f"Cancelled order {order_id}")
            return True
        return False

    def get_order_book_snapshot(self, depth: int = 20) -> Dict:
        bids = []
        asks = []

        buy_prices = sorted(self.price_levels_buy.keys(), reverse=True)
        for price in buy_prices[:depth]:
            total_quantity = Decimal('0')
            for order_id in self.price_levels_buy[price]:
                order = self.order_map.get(order_id)
                if order and not order.is_filled() and order.status == OrderStatus.PENDING:
                    total_quantity += order.remaining_quantity()

            if total_quantity > 0:
                bids.append({
                    'price': float(price),
                    'quantity': float(total_quantity),
                    'total': float(price * total_quantity)
                })

        sell_prices = sorted(self.price_levels_sell.keys())
        for price in sell_prices[:depth]:
            total_quantity = Decimal('0')
            for order_id in self.price_levels_sell[price]:
                order = self.order_map.get(order_id)
                if order and not order.is_filled() and order.status == OrderStatus.PENDING:
                    total_quantity += order.remaining_quantity()
            
            if total_quantity > 0:
                asks.append({
                    'price': float(price),
                    'quantity': float(total_quantity),
                    'total': float(price * total_quantity)
                })
        
        return {
            'pair': self.pair,
            'bids': bids,
            'asks': asks,
            'success': True,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }

class MatchingEngine:
    def __init__(self):
        self.order_books: Dict[str, OrderBook] = {}
        self.trades: List[Trade] = []
        self.trade_history: Dict[str, List[Trade]] = defaultdict(list)
        self.user_orders: Dict[str, List[str]] = defaultdict(list)
        
        self.stats = {
            'total_orders': 0,
            'total_trades': 0,
            'total_volume': Decimal('0'),
            'active_orders': 0
        }
    
    def get_or_create_order_book(self, pair: str) -> OrderBook:
        """Get or create order book for trading pair"""
        if pair not in self.order_books:
            self.order_books[pair] = OrderBook(pair)
            logger.info(f"Created new order book for {pair}")
        return self.order_books[pair]
    
    def place_order(self, order_data: Dict) -> Tuple[Order, List[Trade]]:
        try:
            order = Order(
                timestamp=time.time(),
                order_id=str(uuid.uuid4()),
                user_id=order_data['user_id'],
                pair=order_data['pair'],
                order_type=order_data['order_type'],
                price=Decimal(str(order_data['price'])),
                quantity=Decimal(str(order_data['quantity']))
            )
            
            if not self._validate_order(order):
                order.status = OrderStatus.REJECTED
                logger.warning(f"Order rejected: {order.order_id}")
                return order, []
            
            order_book = self.get_or_create_order_book(order.pair)

            if order.order_type in [OrderType.BUY, OrderType.MARKET_BUY]:
                executed_trades = self._match_buy_order(order, order_book)
            else:
                executed_trades = self._match_sell_order(order, order_book)
            
            if not order.is_filled() and order.order_type in [OrderType.BUY, OrderType.SELL]:
                order_book.add_order(order)
                self.stats['active_orders'] += 1
            
            self.stats['total_orders'] += 1
            self.stats['total_trades'] += len(executed_trades)
            
            self.user_orders[order.user_id].append(order.order_id)
            
            logger.info(f"Placed order {order.order_id}: {order.order_type.value} {order.quantity} {order.pair} @ {order.price}. Executed {len(executed_trades)} trades.")
            
            return order, executed_trades
            
        except Exception as e:
            logger.error(f"Error placing order: {e}", exc_info=True)
            error_order = Order(
                timestamp=time.time(),
                order_id=str(uuid.uuid4()),
                user_id=order_data.get('user_id', 'unknown'),
                pair=order_data.get('pair', 'UNKNOWN'),
                order_type=order_data.get('order_type', OrderType.BUY),
                price=Decimal('0'),
                quantity=Decimal('0'),
                status=OrderStatus.REJECTED
            )
            return error_order, []
    
    def _validate_order(self, order: Order) -> bool:
        if order.quantity <= Decimal('0'):
            logger.warning(f"Invalid quantity: {order.quantity}")
            return False
        
        if order.price <= Decimal('0') and order.order_type in [OrderType.BUY, OrderType.SELL]:
            logger.warning(f"Invalid price: {order.price}")
            return False
        
        return True
    
    def _match_buy_order(self, buy_order: Order, order_book: OrderBook) -> List[Trade]:
        executed_trades = []
        
        try:
            while buy_order.remaining_quantity() > Decimal('0'):
                best_sell = order_book.get_best_sell_order()

                if not best_sell:
                    break
                if buy_order.order_type == OrderType.BUY and best_sell.price > buy_order.price:
                    break
                elif buy_order.order_type == OrderType.MARKET_BUY:
                    pass
                
                trade = self._execute_trade(buy_order, best_sell)
                executed_trades.append(trade)
                
                if best_sell.is_filled():
                    self.stats['active_orders'] -= 1
        except Exception as e:
            logger.error(f"Error matching buy order: {e}", exc_info=True)
        
        return executed_trades
    
    def _match_sell_order(self, sell_order: Order, order_book: OrderBook) -> List[Trade]:
        executed_trades = []
        
        try:
            while sell_order.remaining_quantity() > Decimal('0'):
                best_buy = order_book.get_best_buy_order()
                
                if not best_buy:
                    break
                if sell_order.order_type == OrderType.SELL and best_buy.price < sell_order.price:
                    break

                trade = self._execute_trade(best_buy, sell_order)
                executed_trades.append(trade)

                if best_buy.is_filled():
                    self.stats['active_orders'] -= 1
        except Exception as e:
            logger.error(f"Error matching sell order: {e}", exc_info=True)
        
        return executed_trades
    
    def _execute_trade(self, buy_order: Order, sell_order: Order) -> Trade:
        trade_quantity = min(buy_order.remaining_quantity(), sell_order.remaining_quantity())
        trade_price = sell_order.price
        
        buy_order.fill(trade_quantity)
        sell_order.fill(trade_quantity)
        
        trade = Trade(
            trade_id=str(uuid.uuid4()),
            pair=buy_order.pair,
            price=trade_price,
            quantity=trade_quantity,
            buyer_id=buy_order.user_id,
            seller_id=sell_order.user_id,
            buyer_order_id=buy_order.order_id,
            seller_order_id=sell_order.order_id,
            timestamp=datetime.now(timezone.utc)
        )
        
        self.trades.append(trade)
        self.trade_history[buy_order.pair].append(trade)
        self.stats['total_volume'] += trade_price * trade_quantity
        
        logger.info(f"Executed trade: {trade_quantity} {buy_order.pair} @ {trade_price}")
        
        return trade
    
    def cancel_order(self, order_id: str, user_id: str) -> bool:
        for order_book in self.order_books.values():
            if order_id in order_book.order_map:
                order = order_book.order_map[order_id]
                if order.user_id == user_id:
                    success = order_book.cancel_order(order_id)
                    if success:
                        self.stats['active_orders'] -= 1
                    return success
        return False
    
    def get_order_book(self, pair: str, depth: int = 20) -> Dict:
        order_book = self.get_or_create_order_book(pair)
        return order_book.get_order_book_snapshot(depth)
    
    def get_recent_trades(self, pair: str, limit: int = 50) -> List[Dict]:
        trades = self.trade_history.get(pair, [])
        recent_trades = sorted(trades, key=lambda t: t.timestamp, reverse=True)[:limit]
        return [trade.to_dict() for trade in recent_trades]
    
    def get_user_orders(self, user_id: str) -> List[Dict]:
        user_order_data = []
        
        for order_book in self.order_books.values():
            for order_id in self.user_orders.get(user_id, []):
                if order_id in order_book.order_map:
                    order = order_book.order_map[order_id]
                    user_order_data.append(order.to_dict())
        
        return sorted(user_order_data, key=lambda x: x['timestamp'], reverse=True)
    
    def get_stats(self) -> Dict:
        return {
            'total_orders': self.stats['total_orders'],
            'total_trades': self.stats['total_trades'],
            'total_volume': float(self.stats['total_volume']),
            'active_orders': self.stats['active_orders'],
            'active_pairs': len(self.order_books),
            'uptime': time.time()
        }

matching_engine = MatchingEngine()
