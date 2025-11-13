import logging
import time
from models import EthereumWallet

logger = logging.getLogger(__name__)


class DepositMonitor:
    def __init__(self, check_interval=30):
        self.check_interval = check_interval
        self.running = False

    def start(self):
        self.running = True
        logger.info("Deposit monitor started")

        while self.running:
            try:
                self.check_all_deposits()
                time.sleep(self.check_interval)

            except KeyboardInterrupt:
                logger.info("Deposit monitor stopped by user")
                self.running = False
                break

            except Exception as e:
                logger.error(f"Error in deposit monitor: {e}")
                time.sleep(self.check_interval)

    def stop(self):
        self.running = False

    def check_all_deposits(self):
        try:
            from services.wallet_service import wallet_service
            wallets = EthereumWallet.query.filter_by(is_active=True).all()

            logger.info(f"Checking {len(wallets)} deposit addresses")

            deposits_found = 0

            for wallet in wallets:
                try:
                    result = wallet_service.check_deposit(
                        user_id=wallet.user_id,
                        address=wallet.address
                    )

                    if result:
                        deposits_found += 1

                        if result.get('status') == 'completed':
                            logger.info(
                                f"Processed deposit: {result['amount']} ETH "
                                f"for user {wallet.user_id}"
                            )
                        elif result.get('status') == 'pending':
                            logger.info(
                                f"Pending deposit: {result['amount']} ETH "
                                f"({result['confirmations']}/{result['required_confirmations']} confirmations)"
                            )

                except Exception as e:
                    logger.error(f"Error checking wallet {wallet.address}: {e}")
                    continue

            if deposits_found > 0:
                logger.info(f"Found {deposits_found} deposits this round")

        except Exception as e:
            logger.error(f"Error in check_all_deposits: {e}")


deposit_monitor = DepositMonitor(check_interval=30)


def start_deposit_monitor(app):
    import threading
    print("Starting deposit monitor")
    def monitor():
        with app.app_context():
            deposit_monitor = DepositMonitor(check_interval=30)
            deposit_monitor.start()

    thread = threading.Thread(target=monitor, daemon=True)
    thread.start()

    return thread
