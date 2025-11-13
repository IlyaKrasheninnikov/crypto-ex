from decimal import Decimal


class FeeService:
    def __init__(self, config=None):
        if config is None:
            from config import Config
            config = Config()

        self.maker_fee_rate = Decimal(str(getattr(config, 'MAKER_FEE_RATE', 0.001)))
        self.taker_fee_rate = Decimal(str(getattr(config, 'TAKER_FEE_RATE', 0.002)))
        self.withdrawal_fee_rate = Decimal(str(getattr(config, 'WITHDRAWAL_FEE_RATE', 0.0005)))

        self.vip_tiers = getattr(config, 'VIP_TIERS', {
            'VIP0': {'maker_fee': Decimal('0.001'), 'taker_fee': Decimal('0.002')},
            'VIP1': {'maker_fee': Decimal('0.0009'), 'taker_fee': Decimal('0.0018')},
            'VIP2': {'maker_fee': Decimal('0.0008'), 'taker_fee': Decimal('0.0016')},
            'VIP3': {'maker_fee': Decimal('0.0006'), 'taker_fee': Decimal('0.0012')}
        })

    def calculate_fee(self, trade_value, vip_tier='VIP0', is_maker=False):
        trade_value = Decimal(str(trade_value))

        tier_config = self.vip_tiers.get(vip_tier, self.vip_tiers['VIP0'])

        if is_maker:
            fee_rate = tier_config['maker_fee']
        else:
            fee_rate = tier_config['taker_fee']

        return trade_value * fee_rate

    def calculate_maker_fee(self, trade_value, vip_tier='VIP0'):
        return self.calculate_fee(trade_value, vip_tier, is_maker=True)

    def calculate_taker_fee(self, trade_value, vip_tier='VIP0'):
        return self.calculate_fee(trade_value, vip_tier, is_maker=False)

    def calculate_withdrawal_fee(self, amount):
        return Decimal(str(amount)) * self.withdrawal_fee_rate

    def get_fee_rates(self, vip_tier='VIP0'):
        tier_config = self.vip_tiers.get(vip_tier, self.vip_tiers['VIP0'])
        return {
            'maker': float(tier_config['maker_fee']),
            'taker': float(tier_config['taker_fee']),
            'withdrawal': float(self.withdrawal_fee_rate)
        }
