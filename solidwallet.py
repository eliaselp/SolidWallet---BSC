import os
import json
import pickle
import qrcode
import math
import logging
from io import BytesIO
import traceback
from datetime import datetime, timedelta
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from web3 import Web3
try:
    from web3.middleware import geth_poa_middleware
except ImportError:
    from web3.middleware.geth_poa import geth_poa_middleware
from dotenv import load_dotenv
from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, 
                            QWidget, QLabel, QLineEdit, QPushButton, QTableWidget,
                            QComboBox, QFileDialog, QMessageBox, QListWidget, 
                            QTabWidget, QFormLayout, QGroupBox, QInputDialog,
                            QTableWidgetItem, QStyle, QHeaderView, QListWidgetItem,
                            QProgressBar, QStackedWidget, QDialog, QDialogButtonBox, QGraphicsDropShadowEffect, QScrollArea,
                            QFrame, QSlider)
from PyQt5.QtGui import (QPixmap, QImage, QIcon, QPainter, QBrush, QPen, QColor,
                        QFont, QPainterPath, QDoubleValidator, QIntValidator, QRadialGradient, QConicalGradient)
from PyQt5.QtCore import (Qt, QTimer, QSize, QFile, QIODevice, pyqtSignal, QThread, QRectF, QPropertyAnimation, QEasingCurve, QPoint)
import resources_rc


# Configuración inicial de logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='solidwallet.log',
    filemode='w'
)
logger = logging.getLogger(__name__)

load_dotenv()
INFURA_URL = os.getenv('INFURA_URL', 'https://bsc-dataseed.binance.org/')

# Contratos de tokens ERC-20 en BSC
TOKEN_CONTRACTS = {
    'USDT': Web3.to_checksum_address('0x55d398326f99059fF775485246999027B3197955'),
    'USDC': Web3.to_checksum_address('0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d'),
    'BNB': None  # BNB es la moneda nativa
}

TOKEN_DECIMALS = {
    'USDT': 18,
    'USDC': 18,
    'BNB': 18
}

# Tiempo de sesión en minutos
SESSION_TIMEOUT = 10

class Worker(QThread):
    finished = pyqtSignal(object)
    error = pyqtSignal(str)

    def __init__(self, func, *args, **kwargs):
        super().__init__()
        self.func = func
        self.args = args
        self.kwargs = kwargs
        self._is_running = True
        logger.debug(f"Worker creado para función: {func.__name__}")

    def run(self):
        try:
            logger.debug(f"Iniciando ejecución del worker para función: {self.func.__name__}")
            result = self.func(*self.args, **self.kwargs)
            if self._is_running:
                self.finished.emit(result)
            logger.debug(f"Worker completado exitosamente para función: {self.func.__name__}")
        except Exception as e:
            if self._is_running:
                self.error.emit(str(e))
                logger.error(f"Error en worker para función {self.func.__name__}: {str(e)}\n{traceback.format_exc()}")
        finally:
            self._is_running = False
            logger.debug(f"Worker finalizado para función: {self.func.__name__}")

    def stop(self):
        logger.debug(f"Solicitando detención del worker para función: {self.func.__name__}")
        self._is_running = False
        self.quit()
        if not self.wait(1000):  # Esperar 1 segundo para que termine
            logger.warning(f"Worker no respondió a solicitud de detención, terminando forzadamente")
            self.terminate()
            self.wait()

class LoadingWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.angle = 0
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_animation)
        self.timer.start(30)
        self.setMinimumSize(200, 200)
        
        self.layout = QVBoxLayout(self)
        self.layout.setAlignment(Qt.AlignCenter)
        
        self.text_label = QLabel("Cargando...")
        self.text_label.setStyleSheet("""
            font-size: 16px;
            font-weight: bold;
            color: #4e9af1;
            margin-top: 20px;
        """)
        self.text_label.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(self.text_label)

    def update_animation(self):
        self.angle = (self.angle + 12) % 360
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        size = min(self.width(), self.height()) - 40
        x = int((self.width() - size) / 2)
        y = int((self.height() - size) / 2) - 20
        
        # Gradiente radial para el fondo
        radial_gradient = QRadialGradient(x + size/2, y + size/2, size/2)
        radial_gradient.setColorAt(0, QColor(78, 154, 241, 30))
        radial_gradient.setColorAt(1, QColor(78, 154, 241, 5))
        
        painter.setPen(Qt.NoPen)
        painter.setBrush(QBrush(radial_gradient))
        painter.drawEllipse(x, y, size, size)
        
        # Gradiente cónico para el arco
        pen = QPen(QColor(78, 154, 241), 10)
        pen.setCapStyle(Qt.RoundCap)
        
        conical_gradient = QConicalGradient(x + size/2, y + size/2, self.angle)
        conical_gradient.setColorAt(0, QColor(78, 154, 241))
        conical_gradient.setColorAt(0.5, QColor(120, 180, 255))
        conical_gradient.setColorAt(1, QColor(78, 154, 241))
        
        pen.setBrush(QBrush(conical_gradient))
        painter.setPen(pen)
        
        start_angle = self.angle * 16
        span_angle = 180 * 16
        rect = QRectF(x, y, size, size)
        painter.drawArc(rect, start_angle, span_angle)
        
        # Puntos decorativos
        dot_size = 8
        for i in range(0, 360, 30):
            rad = math.radians(i + self.angle)
            dot_x = x + size/2 + (size/2 - 10) * math.cos(rad) - dot_size/2
            dot_y = y + size/2 + (size/2 - 10) * math.sin(rad) - dot_size/2
            
            dot_color = QColor(78, 154, 241)
            dot_color.setAlpha(100 + int(155 * (1 - abs(i - 180)/180)))
            
            painter.setPen(Qt.NoPen)
            painter.setBrush(dot_color)
            painter.drawEllipse(QRectF(dot_x, dot_y, dot_size, dot_size))

class CryptoWallet:
    def __init__(self, private_key=None):
        logger.debug("Inicializando CryptoWallet")
        self.web3 = Web3(Web3.HTTPProvider(INFURA_URL))
        self.web3.middleware_onion.inject(geth_poa_middleware, layer=0)
        
        if private_key:
            logger.debug("Creando wallet con private key existente")
            self.account = self.web3.eth.account.from_key(private_key)
        else:
            logger.debug("Creando nuevo wallet")
            self.account = self.web3.eth.account.create()
        
        self.address = self.account.address
        self.private_key = self.account.key.hex()
        logger.debug(f"Wallet creado con dirección: {self.address}")
        
    def get_balance(self, token_symbol='BNB'):
        logger.debug(f"Obteniendo balance para {token_symbol}")
        try:
            if token_symbol == 'BNB':
                balance = self.web3.eth.get_balance(self.address)
                return self.web3.from_wei(balance, 'ether')
            else:
                contract = self.web3.eth.contract(
                    address=TOKEN_CONTRACTS[token_symbol],
                    abi=self._get_erc20_abi()
                )
                balance = contract.functions.balanceOf(self.address).call()
                return balance / (10 ** TOKEN_DECIMALS[token_symbol])
        except Exception as e:
            logger.error(f"Error obteniendo balance para {token_symbol}: {str(e)}")
            raise
    
    def get_transactions(self, limit=10):
        logger.debug(f"Obteniendo {limit} transacciones")
        transactions = []
        try:
            latest_block = self.web3.eth.block_number
            logger.debug(f"Último bloque: {latest_block}")
            
            for i in range(latest_block, max(0, latest_block - 20), -1):
                block = self.web3.eth.get_block(i, full_transactions=True)
                for tx in block.transactions:
                    if tx['from'] == self.address or tx['to'] == self.address:
                        token = 'BNB'
                        value = self.web3.from_wei(tx['value'], 'ether')
                        
                        if tx['to'] in [TOKEN_CONTRACTS['USDT'], TOKEN_CONTRACTS['USDC']]:
                            try:
                                data = tx['input'][2:]
                                if data.startswith('a9059cbb'):
                                    value = int(data[32:64], 16) / (10 ** 18)
                                    token = 'USDT' if tx['to'] == TOKEN_CONTRACTS['USDT'] else 'USDC'
                            except:
                                pass
                        
                        transactions.append({
                            'hash': tx['hash'].hex(),
                            'from': tx['from'],
                            'to': tx['to'],
                            'value': value,
                            'token': token,
                            'block': i,
                            'status': 'confirmed'
                        })
                        if len(transactions) >= limit:
                            logger.debug(f"Se encontraron {len(transactions)} transacciones")
                            return transactions
        except Exception as e:
            logger.error(f"Error obteniendo transacciones: {e}")
        return transactions
    
    def send_transaction(self, recipient, amount, token_symbol, gas_price=None, gas_limit=None):
        """Envía una transacción con gas optimizado si no se especifica"""
        logger.debug(f"Enviando transacción de {amount} {token_symbol} a {recipient}")
        
        try:
            # Convertir a checksum address
            recipient = Web3.to_checksum_address(recipient)
            
            # Si no se proporcionan parámetros de gas, calcular óptimos
            if gas_price is None or gas_limit is None:
                gas_params = self.calculate_optimal_gas(token_symbol)
                gas_price = gas_params['gas_price']
                gas_limit = gas_params['gas_limit']
            
            # Convertir gas price a wei
            gas_price_wei = self.web3.to_wei(gas_price, 'gwei')
            
            if token_symbol == 'BNB':
                # Transacción nativa de BNB
                tx = {
                    'to': recipient,
                    'value': self.web3.to_wei(amount, 'ether'),
                    'gas': gas_limit,
                    'gasPrice': gas_price_wei,
                    'nonce': self.web3.eth.get_transaction_count(self.address),
                    'chainId': 56  # BSC chain ID
                }
                
                # Firmar y enviar
                signed_tx = self.web3.eth.account.sign_transaction(tx, self.private_key)
                tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
            else:
                # Transacción de token ERC-20
                token_contract = self.web3.eth.contract(
                    address=TOKEN_CONTRACTS[token_symbol],
                    abi=self._get_erc20_abi()
                )
                
                # Calcular amount con decimales correctos
                decimals = TOKEN_DECIMALS[token_symbol]
                amount_wei = int(amount * (10 ** decimals))
                
                tx = token_contract.functions.transfer(
                    recipient,
                    amount_wei
                ).build_transaction({
                    'gas': gas_limit,
                    'gasPrice': gas_price_wei,
                    'nonce': self.web3.eth.get_transaction_count(self.address),
                    'chainId': 56  # BSC chain ID
                })
                
                # Firmar y enviar
                signed_tx = self.web3.eth.account.sign_transaction(tx, self.private_key)
                tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
            
            logger.debug(f"Transacción enviada con hash: {tx_hash.hex()}")
            return tx_hash.hex()
            
        except Exception as e:
            logger.error(f"Error enviando transacción: {str(e)}")
            raise

    def calculate_optimal_gas(self, token_symbol='BNB', speed='medium'):
        """Calcula valores óptimos de gas basados en condiciones de red y velocidad seleccionada"""
        try:
            # Obtener gas price actual de la red
            current_gas = float(self.web3.from_wei(
                self.web3.eth.gas_price, 
                'gwei'
            ))
            
            # Multiplicadores para diferentes velocidades
            speed_multipliers = {
                'low': 0.7,     # Económico
                'medium': 1.0,   # Estándar
                'high': 1.3,     # Rápido
                'urgent': 2.0    # Urgente
            }
            
            # Validar velocidad seleccionada
            if speed not in speed_multipliers:
                speed = 'medium'
            
            gas_price = round(current_gas * speed_multipliers[speed], 1)
            
            # Gas limit según tipo de token
            gas_limit = 21000 if token_symbol == 'BNB' else 100000
            
            return {
                'gas_price': gas_price,
                'gas_limit': gas_limit,
                'speed': speed
            }
            
        except Exception as e:
            logger.error(f"Error calculando gas óptimo: {str(e)}")
            # Valores por defecto seguros
            return {
                'gas_price': 5.0,
                'gas_limit': 21000 if token_symbol == 'BNB' else 100000,
                'speed': 'medium'
            }

    def _get_erc20_abi(self):
        return json.loads('''[
            {"constant":true,"inputs":[{"name":"_owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"balance","type":"uint256"}],"type":"function"},
            {"constant":false,"inputs":[{"name":"_to","type":"address"},{"name":"_value","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"type":"function"},
            {"constant":true,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint8"}],"type":"function"}
        ]''')

class WalletManager:
    def __init__(self):
        logger.debug("Inicializando WalletManager")
        self.wallets = {}
        self.encrypted_wallets = {}
        self.wallet_files = []
        self.load_wallet_files()
        logger.debug(f"WalletManager inicializado con {len(self.wallet_files)} wallets cargados")
    
    def create_wallet(self):
        logger.debug("Creando nuevo wallet")
        return CryptoWallet()
    
    def encrypt_wallet(self, wallet, password, file_path):
        logger.debug(f"Cifrando wallet para guardar en {file_path}")
        try:
            wallet_data = {
                'address': wallet.address,
                'private_key': wallet.private_key,
                'web3_provider': INFURA_URL
            }
            
            salt = get_random_bytes(16)
            key = scrypt(password, salt, key_len=32, N=2**14, r=8, p=1)
            serialized = pickle.dumps(wallet_data)
            
            padding_length = 16 - (len(serialized) % 16)
            serialized += bytes([padding_length]) * padding_length
            
            cipher = AES.new(key, AES.MODE_GCM)
            ciphertext, tag = cipher.encrypt_and_digest(serialized)
            
            encrypted_data = {
                'salt': salt.hex(),
                'nonce': cipher.nonce.hex(),
                'tag': tag.hex(),
                'ciphertext': ciphertext.hex(),
                'address': wallet.address
            }
            
            with open(file_path, 'w') as f:
                json.dump(encrypted_data, f)
            
            self.wallet_files.append(file_path)
            self.save_wallet_files()
            logger.debug(f"Wallet cifrado y guardado exitosamente en {file_path}")
            
            return file_path
        except Exception as e:
            logger.error(f"Error cifrando wallet: {str(e)}")
            raise
    
    def decrypt_wallet(self, file_path, password):
        logger.debug(f"Descifrando wallet desde {file_path}")
        try:
            with open(file_path, 'r') as f:
                encrypted_data = json.load(f)
            
            salt = bytes.fromhex(encrypted_data['salt'])
            nonce = bytes.fromhex(encrypted_data['nonce'])
            tag = bytes.fromhex(encrypted_data['tag'])
            ciphertext = bytes.fromhex(encrypted_data['ciphertext'])
            
            key = scrypt(password, salt, key_len=32, N=2**14, r=8, p=1)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)
            
            padding_length = decrypted[-1]
            decrypted = decrypted[:-padding_length]
            
            wallet_data = pickle.loads(decrypted)
            
            if wallet_data['address'].lower() != encrypted_data['address'].lower():
                logger.error("La dirección del wallet no coincide con los datos cifrados")
                raise ValueError("La dirección del wallet no coincide con los datos cifrados")
            
            logger.debug(f"Wallet descifrado exitosamente: {wallet_data['address']}")
            return CryptoWallet(private_key=wallet_data['private_key'])
        except Exception as e:
            logger.error(f"Error al descifrar el wallet: {str(e)}")
            raise ValueError(f"Error al descifrar el wallet: {str(e)}")
    
    def load_wallet_files(self):
        if os.path.exists('wallets.json'):
            with open('wallets.json', 'r') as f:
                self.wallet_files = json.load(f)
                logger.debug(f"Se cargaron {len(self.wallet_files)} wallets desde wallets.json")
    
    def save_wallet_files(self):
        with open('wallets.json', 'w') as f:
            json.dump(self.wallet_files, f)
            logger.debug("Lista de wallets guardada en wallets.json")

class SolidWalletGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        logger.debug("Inicializando SolidWalletGUI")
        self.wallet_manager = WalletManager()
        self.current_wallet = None
        self.current_file = None
        self.last_activity = datetime.now()
        self.session_timer = QTimer(self)
        self.session_timer.timeout.connect(self.check_session)
        self.session_timer.start(60000)  # 1 minuto
        self.active_workers = []

        # Timer para actualizar gas prices
        self.gas_price_timer = QTimer(self)
        self.gas_price_timer.timeout.connect(self.update_gas_prices)
        self.gas_price_timer.start(5000)  # Actualizar cada 5 segundos
        self.current_gas_prices = {'low': 3, 'medium': 5, 'high': 10, 'urgent': 20}
        self.bnb_price = 280  # Valor por defecto
        
        # Configuración básica de la ventana
        self.setWindowTitle("SolidWallet - BSC Wallet")
        self.resize(1000, 700)
        self.setMinimumSize(1200, 900)
        self.setWindowIcon(self.create_app_icon())
        self.setStyleSheet(self.get_stylesheet())
        
        # Centrar la ventana en la pantalla
        self.center_on_screen()

        # Widget de loading
        self.loading_widget = LoadingWidget()
        self.loading_widget.setVisible(False)
        
        # Widget principal
        self.central_widget = QWidget()
        self.main_layout = QHBoxLayout()
        self.main_layout.setContentsMargins(15, 15, 15, 15)
        self.main_layout.setSpacing(15)
        self.central_widget.setLayout(self.main_layout)
        
        # Configurar paneles
        self.setup_left_panel()
        self.setup_empty_right_panel()
        self.setup_wallet_right_panel()
        
        # Widget para "no wallet" (pantalla inicial)
        self.no_wallet_widget = self.create_no_wallet_widget()
        
        # Stack principal
        self.stacked_widget = QStackedWidget()
        self.stacked_widget.addWidget(self.central_widget)
        
        loading_container = QWidget()
        loading_layout = QVBoxLayout()
        loading_layout.addWidget(self.loading_widget, 0, Qt.AlignCenter)
        loading_container.setLayout(loading_layout)
        self.stacked_widget.addWidget(loading_container)
        
        self.stacked_widget.addWidget(self.no_wallet_widget)
        self.setCentralWidget(self.stacked_widget)
        
        # Estado de conectividad
        self.online = True
        self.connectivity_icon = QLabel()
        self.connectivity_icon.setFixedSize(32, 32)
        self.connectivity_icon.setScaledContents(True)
        self.update_connectivity_icon()
        
        # Configurar timer para verificar conectividad
        self.connectivity_timer = QTimer(self)
        self.connectivity_timer.timeout.connect(self.check_connectivity)
        self.connectivity_timer.start(10000)  # Verificar cada 10 segundos
        
        # Agregar icono de conectividad a la barra de estado
        self.statusBar().addPermanentWidget(self.connectivity_icon)
        self.statusBar().showMessage("Conectado", 3000)
        
        # Mostrar vista inicial
        if self.wallet_manager.wallet_files:
            self.stacked_widget.setCurrentIndex(0)
            self.show_empty_state()
        else:
            self.stacked_widget.setCurrentIndex(2)

    def center_on_screen(self):
        """Centra la ventana en la pantalla principal"""
        frame_geometry = self.frameGeometry()
        center_point = QApplication.desktop().availableGeometry().center()
        frame_geometry.moveCenter(center_point)
        self.move(frame_geometry.topLeft())

    def check_connectivity(self):
        """Verifica la conectividad a internet"""
        try:
            import socket
            socket.setdefaulttimeout(3)
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(("8.8.8.8", 53))
            if not self.online:
                self.set_online(True)
        except:
            if self.online:
                self.set_online(False)

    def set_online(self, status):
        """Actualiza el estado de conectividad"""
        self.online = status
        self.update_connectivity_icon()
        
        if status:
            self.statusBar().showMessage("Conectado", 3000)
            logger.info("Conexión restablecida")
        else:
            self.statusBar().showMessage("Sin conexión a internet", 3000)
            logger.warning("Sin conexión a internet")
        
        self.update_ui_for_connectivity()

    def update_ui_for_connectivity(self):
        """Habilita/deshabilita controles según conectividad"""
        enable = self.online
        
        self.btn_new.setEnabled(enable)
        self.btn_load.setEnabled(enable)
        self.btn_delete.setEnabled(enable)
        self.send_button.setEnabled(enable)
        
        if not enable:
            QMessageBox.warning(self, "Sin conexión", 
                              "No se puede conectar a internet. Algunas funciones estarán limitadas.")

    def update_connectivity_icon(self):
        """Actualiza el ícono de conectividad con tamaño aumentado"""
        icon_size = QSize(32, 32)
        
        if self.online:
            icon = QIcon(":/icons/online.svg")
            self.connectivity_icon.setPixmap(icon.pixmap(icon_size))
            self.connectivity_icon.setToolTip("Conectado a internet")
        else:
            icon = QIcon(":/icons/offline.svg")
            self.connectivity_icon.setPixmap(icon.pixmap(icon_size))
            self.connectivity_icon.setToolTip("Sin conexión a internet")
        
        self.connectivity_icon.setFixedSize(icon_size)

    def update_gas_prices(self):
        """Actualiza los precios de gas con manejo de tipos correcto"""
        if not self.online:
            self.show_connectivity_error()
            return

        try:
            if not self.current_wallet:
                return

            # Obtener gas price actual de la red
            current_gas = float(self.current_wallet.web3.from_wei(
                self.current_wallet.web3.eth.gas_price, 'gwei'
            ))
            
            # Obtener precio de BNB
            try:
                self.bnb_price = float(self.get_bnb_price())
            except Exception as e:
                logger.error(f"No se pudo obtener precio BNB: {str(e)}")
                self.bnb_price = 280  # Valor por defecto si falla
                
            # Calcular niveles de gas price
            self.current_gas_prices = {
                'low': max(1.0, round(current_gas * 0.7, 1)),
                'medium': round(current_gas, 1),
                'high': round(current_gas * 1.3, 1),
                'urgent': round(current_gas * 2.0, 1)
            }
            
            # Actualizar el combo box de velocidad
            if hasattr(self, 'speed_combo'):
                self.speed_combo.setItemText(0, f"Económica ({self.current_gas_prices['low']} gwei)")
                self.speed_combo.setItemText(1, f"Estándar ({self.current_gas_prices['medium']} gwei)")
                self.speed_combo.setItemText(2, f"Rápida ({self.current_gas_prices['high']} gwei)")
                self.speed_combo.setItemText(3, f"Urgente ({self.current_gas_prices['urgent']} gwei)")
            
            self.update_estimated_fee()
            
        except Exception as e:
            logger.error(f"Error en update_gas_prices: {str(e)}")

    def show_empty_state(self):
        self.empty_right_panel.setVisible(True)
        self.wallet_right_panel.setVisible(False)
        self.reset_wallet_info()

    def show_wallet_state(self):
        self.empty_right_panel.setVisible(False)
        self.wallet_right_panel.setVisible(True)

    def reset_wallet_info(self):
        self.address_label.setText("No hay billetera cargada")
        self.bnb_balance.setText("0.0")
        self.usdt_balance.setText("0.0")
        self.usdc_balance.setText("0.0")
        self.qr_code_label.clear()
        self.qr_code_label.setText("Seleccione una billetera")
        self.qr_code_label.setStyleSheet("color: #666; font-style: italic;")
        self.transaction_table.setRowCount(0)
        
    def setup_empty_right_panel(self):
        self.empty_right_panel = QWidget()
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignCenter)
        layout.setContentsMargins(40, 40, 40, 40)
        
        # Contenedor principal
        card = QWidget()
        card.setStyleSheet("""
            background-color: white;
            border-radius: 16px;
            padding: 40px;
        """)
        
        # Efecto de sombra
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(25)
        shadow.setColor(QColor(0, 0, 0, 15))
        shadow.setOffset(0, 5)
        card.setGraphicsEffect(shadow)
        
        card_layout = QVBoxLayout(card)
        card_layout.setAlignment(Qt.AlignCenter)
        card_layout.setSpacing(20)

        icon_label = QLabel()
        icon_label.setAlignment(Qt.AlignCenter)
        icon_label.setStyleSheet("background: transparent; padding: 0; margin: 0;")
        
        original_pixmap = QPixmap(":/icons/no_wallet.png")
        max_size = 200
        
        if original_pixmap.width() > original_pixmap.height():
            scaled_pixmap = original_pixmap.scaledToWidth(max_size, Qt.SmoothTransformation)
        else:
            scaled_pixmap = original_pixmap.scaledToHeight(max_size, Qt.SmoothTransformation)
        
        icon_label.setPixmap(scaled_pixmap)
        
        icon_container = QWidget()
        icon_container.setFixedSize(max_size, max_size)
        icon_layout = QHBoxLayout(icon_container)
        icon_layout.setContentsMargins(0, 0, 0, 0)
        icon_layout.addWidget(icon_label)

        title = QLabel("Billetera Desconectada")
        title.setStyleSheet("""
            font-size: 24px;
            font-weight: 600;
            color: #333;
            margin-top: 20px;
        """)
        
        card_layout.addWidget(icon_container, 0, Qt.AlignCenter)
        card_layout.addWidget(title, 0, Qt.AlignCenter)
        
        layout.addWidget(card)
        self.empty_right_panel.setLayout(layout)
        self.main_layout.addWidget(self.empty_right_panel, 1)
    
    def setup_wallet_right_panel(self):
        self.wallet_right_panel = QWidget()
        layout = QVBoxLayout()
        layout.setSpacing(15)
        
        self.tabs = QTabWidget()
        self.setup_info_tab()
        self.setup_tx_tab()
        self.setup_send_tab()
        
        self.disconnect_btn = QPushButton("Desconectar Billetera")
        self.disconnect_btn.setIcon(self.style().standardIcon(QStyle.SP_DialogCloseButton))
        self.disconnect_btn.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                padding: 8px 16px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #d32f2f;
            }
        """)
        self.disconnect_btn.clicked.connect(self.logout)
        
        layout.addWidget(self.tabs)
        layout.addWidget(self.disconnect_btn)
        self.wallet_right_panel.setLayout(layout)
        self.wallet_right_panel.setVisible(False)
        self.main_layout.addWidget(self.wallet_right_panel, 1)

    def closeEvent(self, event):
        """Manejar el cierre de la aplicación de forma segura"""
        logger.debug("Iniciando cierre de la aplicación")
        
        for worker in self.active_workers:
            try:
                logger.debug(f"Deteniendo worker {id(worker)}")
                worker.stop()
            except Exception as e:
                logger.error(f"Error deteniendo worker: {str(e)}\n{traceback.format_exc()}")
        
        self.cleanup_workers()
        
        if self.active_workers:
            logger.warning(f"Aún hay {len(self.active_workers)} workers activos después de limpieza")
            reply = QMessageBox.question(
                self, 'Workers activos',
                'Algunas operaciones todavía están en curso. ¿Desea forzar el cierre?',
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )
            if reply == QMessageBox.No:
                logger.debug("Usuario canceló el cierre")
                event.ignore()
                return
        
        logger.debug("Aplicación lista para cerrarse")
        event.accept()

    def create_no_wallet_widget(self):
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignCenter)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(25)
        
        logo_label = QLabel()
        pixmap = QPixmap(":/icons/solidwallet.png").scaled(250, 250, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        logo_label.setPixmap(pixmap)
        logo_label.setAlignment(Qt.AlignCenter)
        
        title = QLabel("SolidWallet")
        title.setStyleSheet("""
            QLabel {
                font-size: 32px;
                font-weight: bold;
                color: #4e9af1;
                margin-bottom: 10px;
                padding: 5px;
            }
        """)
        
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(10)
        shadow.setColor(QColor(0, 0, 0, 80))
        shadow.setOffset(2, 2)
        title.setGraphicsEffect(shadow)
        title.setAlignment(Qt.AlignCenter)
        
        subtitle = QLabel("Tu billetera segura para Binance Smart Chain")
        subtitle.setStyleSheet("""
            QLabel {
                font-size: 16px;
                color: #666;
                margin-bottom: 30px;
                font-style: italic;
            }
        """)
        subtitle.setAlignment(Qt.AlignCenter)
        
        btn_container = QWidget()
        btn_container.setStyleSheet("""
            QWidget {
                background-color: #ffffff;
                border-radius: 10px;
                padding: 20px;
            }
        """)
        
        container_shadow = QGraphicsDropShadowEffect()
        container_shadow.setBlurRadius(15)
        container_shadow.setColor(QColor(0, 0, 0, 30))
        container_shadow.setOffset(0, 5)
        btn_container.setGraphicsEffect(container_shadow)
        
        btn_layout = QVBoxLayout()
        btn_layout.setContentsMargins(50, 20, 50, 20)
        btn_layout.setSpacing(20)
        
        btn_create = QPushButton(" Crear Nueva Billetera")
        btn_create.setIcon(self.style().standardIcon(QStyle.SP_FileIcon))
        btn_create.setIconSize(QSize(24, 24))
        btn_create.setStyleSheet("""
            QPushButton {
                background-color: #4e9af1;
                color: white;
                border: none;
                padding: 15px 30px;
                border-radius: 8px;
                font-size: 16px;
                font-weight: bold;
                min-width: 250px;
            }
            QPushButton:hover {
                background-color: #3a7bc8;
            }
            QPushButton:pressed {
                background-color: #2c5fa6;
            }
        """)
        btn_create.clicked.connect(self.create_new_wallet)
        
        btn_load = QPushButton(" Cargar Billetera Existente")
        btn_load.setIcon(self.style().standardIcon(QStyle.SP_DialogOpenButton))
        btn_load.setIconSize(QSize(24, 24))
        btn_load.setStyleSheet("""
            QPushButton {
                background-color: white;
                color: #4e9af1;
                border: 2px solid #4e9af1;
                padding: 15px 30px;
                border-radius: 8px;
                font-size: 16px;
                font-weight: bold;
                min-width: 250px;
            }
            QPushButton:hover {
                background-color: #f0f7ff;
            }
            QPushButton:pressed {
                background-color: #e0eefd;
            }
        """)
        btn_load.clicked.connect(self.load_wallet)
        
        btn_layout.addWidget(btn_create)
        btn_layout.addWidget(btn_load)
        btn_container.setLayout(btn_layout)
        
        layout.addWidget(logo_label)
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addWidget(btn_container)
        layout.addStretch()
        
        widget.setLayout(layout)
        return widget

    def get_stylesheet(self):
        return """
            QMainWindow { background-color: #f5f7fa; }
            QLabel { color: #333; font-weight: 500; }
            QPushButton {
                background-color: #4e9af1; color: white; border: none;
                padding: 8px 16px; border-radius: 4px; font-weight: 500;
                min-width: 100px;
            }
            QPushButton:hover { background-color: #3a7bc8; }
            QPushButton:pressed { background-color: #2c5fa6; }
            QPushButton:disabled { background-color: #cccccc; color: #666666; }
            QTextEdit, QLineEdit, QListWidget {
                border: 1px solid #ddd; border-radius: 4px;
                padding: 6px; background-color: white;
            }
            QTabWidget::pane { border: 1px solid #ddd; border-radius: 4px; background: white; margin-top: -1px; }
            QTabBar::tab { background: #e1e5eb; padding: 8px 16px; border-top-left-radius: 4px; border-top-right-radius: 4px; margin-right: 4px; }
            QTabBar::tab:selected { background: white; border-bottom: 2px solid #4e9af1; }
            QGroupBox { border: 1px solid #ddd; border-radius: 4px; margin-top: 10px; padding-top: 15px; font-weight: bold; background: white; }
            QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 3px; }
            QTableWidget { border: 1px solid #ddd; border-radius: 4px; background: white; gridline-color: #eee; }
            QTableWidget QHeaderView::section { background-color: #f0f0f0; padding: 5px; border: none; }
            QListWidget { border: 1px solid #ddd; border-radius: 4px; background: white; }
            QListWidget::item { padding: 5px; border-bottom: 1px solid #eee; }
            QListWidget::item:selected { background-color: #e0e0e0; color: #333; }
        """
    
    def create_app_icon(self):
        return QIcon(":/icons/solidwallet.png")
    
    def setup_left_panel(self):
        left_panel = QWidget()
        left_panel.setFixedWidth(300)
        left_layout = QVBoxLayout()
        left_layout.setContentsMargins(10, 10, 10, 10)
        left_layout.setSpacing(10)
        
        title = QLabel("Mis Billeteras")
        title.setStyleSheet("""
            QLabel {
                font-size: 18px;
                font-weight: bold;
                color: #4e9af1;
                padding-bottom: 10px;
                border-bottom: 2px solid #4e9af1;
            }
        """)
        left_layout.addWidget(title)
        
        scroll_container = QWidget()
        scroll_layout = QVBoxLayout(scroll_container)
        scroll_layout.setContentsMargins(0, 0, 0, 0)
        
        self.wallet_list = QListWidget()
        self.wallet_list.setIconSize(QSize(24, 24))
        self.wallet_list.setStyleSheet("""
            QListWidget {
                background-color: white;
                border-radius: 5px;
                padding: 5px;
            }
            QListWidget::item {
                padding: 8px;
                border-bottom: 1px solid #eee;
            }
            QListWidget::item:hover {
                background-color: #f0f7ff;
            }
            QListWidget::item:selected {
                background-color: #4e9af1;
                color: white;
                border-radius: 3px;
            }
        """)
        self.wallet_list.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
        self.wallet_list.itemClicked.connect(self.select_wallet)
        self.load_wallet_list()
        
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setWidget(self.wallet_list)
        scroll_area.setStyleSheet("""
            QScrollArea {
                border: none;
            }
            QScrollBar:vertical {
                width: 10px;
                background: #f0f0f0;
            }
            QScrollBar::handle:vertical {
                background: #c0c0c0;
                min-height: 20px;
                border-radius: 5px;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
        """)
        
        scroll_layout.addWidget(scroll_area)
        left_layout.addWidget(scroll_container, 1)
        
        self.btn_new = QPushButton("Nueva Billetera")
        self.btn_new.setIcon(self.style().standardIcon(QStyle.SP_FileIcon))
        self.btn_new.setStyleSheet("""
            QPushButton {
                background-color: #4e9af1;
                color: white;
                padding: 10px;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #3a7bc8;
            }
        """)
        self.btn_new.clicked.connect(self.create_new_wallet)
        left_layout.addWidget(self.btn_new)
        
        self.btn_load = QPushButton("Cargar Billetera")
        self.btn_load.setIcon(self.style().standardIcon(QStyle.SP_DialogOpenButton))
        self.btn_load.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                padding: 10px;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #3d8b40;
            }
        """)
        self.btn_load.clicked.connect(self.load_wallet)
        left_layout.addWidget(self.btn_load)
        
        self.btn_delete = QPushButton("Eliminar Billetera")
        self.btn_delete.setIcon(self.style().standardIcon(QStyle.SP_TrashIcon))
        self.btn_delete.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                padding: 10px;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #d32f2f;
            }
        """)
        self.btn_delete.clicked.connect(self.delete_selected_wallet)
        left_layout.addWidget(self.btn_delete)
        
        left_panel.setLayout(left_layout)
        self.main_layout.addWidget(left_panel)
        
    def delete_selected_wallet(self):
        selected = self.wallet_list.currentItem()
        if not selected:
            QMessageBox.warning(self, "Advertencia", "Seleccione una billetera para eliminar")
            return
        
        file_path = selected.data(Qt.UserRole)
        
        reply = QMessageBox.question(
            self, 'Confirmar', 
            f'¿Eliminar {os.path.basename(file_path)} de la lista?\n(No se eliminará el archivo)',
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            try:
                if file_path == self.current_file:
                    self.logout()
                
                self.wallet_manager.wallet_files.remove(file_path)
                self.wallet_manager.save_wallet_files()
                self.load_wallet_list()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"No se pudo eliminar: {str(e)}")

    def setup_info_tab(self):
        """Configura la pestaña de información del wallet"""
        self.info_tab = QWidget()
        info_layout = QVBoxLayout()
        info_layout.setContentsMargins(15, 15, 15, 15)
        info_layout.setSpacing(15)
        
        address_group = QGroupBox("Dirección de la Billetera")
        address_layout = QVBoxLayout()
        self.address_label = QLabel("No hay billetera cargada")
        self.address_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.address_label.setStyleSheet("""
            QLabel {
                font-family: monospace; 
                background-color: #f8f9fa;
                padding: 10px;
                border-radius: 5px;
                border: 1px solid #dee2e6;
            }
        """)
        address_layout.addWidget(self.address_label)
        address_group.setLayout(address_layout)
        
        balances_group = QGroupBox("Balances")
        balances_layout = QFormLayout()
        
        self.bnb_balance = QLabel("0.0")
        self.usdt_balance = QLabel("0.0")
        self.usdc_balance = QLabel("0.0")
        
        balance_style = "font-weight: bold; font-size: 14px;"
        self.bnb_balance.setStyleSheet(balance_style)
        self.usdt_balance.setStyleSheet(balance_style)
        self.usdc_balance.setStyleSheet(balance_style)
        
        balances_layout.addRow(QLabel("BNB:"), self.bnb_balance)
        balances_layout.addRow(QLabel("USDT:"), self.usdt_balance)
        balances_layout.addRow(QLabel("USDC:"), self.usdc_balance)
        balances_group.setLayout(balances_layout)
        
        qr_group = QGroupBox("Código QR para recibir")
        qr_layout = QVBoxLayout()
        qr_layout.setContentsMargins(0, 0, 0, 20)
        
        self.qr_code_label = QLabel()
        self.qr_code_label.setAlignment(Qt.AlignCenter)
        self.qr_code_label.setFixedSize(250, 250)
        self.qr_code_label.setStyleSheet("""
            QLabel {
                background-color: white;
                border: 1px solid #dee2e6;
                border-radius: 5px;
                padding: 10px;
                margin-bottom: 20px;
            }
        """)
        
        qr_layout.addWidget(self.qr_code_label, 0, Qt.AlignCenter)
        qr_group.setLayout(qr_layout)
        
        info_layout.addWidget(address_group)
        info_layout.addWidget(balances_group)
        info_layout.addWidget(qr_group)
        info_layout.addStretch()
        self.info_tab.setLayout(info_layout)
        
        self.tabs.addTab(self.info_tab, QIcon(":/icons/info.svg"), "Información")
        
    def setup_tx_tab(self):
        """Configura la pestaña de historial de transacciones"""
        self.tx_tab = QWidget()
        tx_layout = QVBoxLayout()
        tx_layout.setContentsMargins(5, 5, 5, 5)
        
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filtrar por moneda:"))
        
        self.tx_filter_combo = QComboBox()
        self.tx_filter_combo.addItems(["Todas", "BNB", "USDT", "USDC"])
        self.tx_filter_combo.currentIndexChanged.connect(self.update_transaction_history)
        filter_layout.addWidget(self.tx_filter_combo)
        filter_layout.addStretch()
        
        tx_layout.addLayout(filter_layout)
        
        self.transaction_table = QTableWidget()
        self.transaction_table.setColumnCount(6)
        self.transaction_table.setHorizontalHeaderLabels(["Hash", "Dirección", "Tipo", "Valor", "Moneda", "Estado"])
        self.transaction_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.transaction_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.transaction_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.transaction_table.setStyleSheet("""
            QTableWidget {
                alternate-background-color: #f8f9fa;
            }
            QHeaderView::section {
                background-color: #e9ecef;
                padding: 5px;
                border: none;
            }
        """)
        
        tx_layout.addWidget(self.transaction_table)
        self.tx_tab.setLayout(tx_layout)
        
        self.tabs.addTab(self.tx_tab, QIcon(":/icons/history.svg"), "Transacciones")

    def update_transaction_history(self):
        """Actualiza el historial de transacciones con los datos del wallet actual"""
        logger.debug("Actualizando historial de transacciones")
        
        if not self.current_wallet:
            logger.debug("No hay wallet cargado, no se puede actualizar historial")
            self.transaction_table.setRowCount(0)
            return
        
        self.show_loading()
        
        def fetch_transactions():
            try:
                transactions = self.current_wallet.get_transactions()
                
                selected_token = self.tx_filter_combo.currentText()
                if selected_token != "Todas":
                    transactions = [tx for tx in transactions if tx.get('token', 'BNB') == selected_token]
                
                return transactions
            except Exception as e:
                logger.error(f"Error obteniendo transacciones: {str(e)}")
                return []

        def update_table(transactions):
            self.transaction_table.setRowCount(len(transactions))
            
            for row, tx in enumerate(transactions):
                if tx['from'].lower() == self.current_wallet.address.lower():
                    tx_type = "Enviado"
                    address = tx['to']
                    type_color = QColor('#f44336')
                else:
                    tx_type = "Recibido"
                    address = tx['from']
                    type_color = QColor('#4CAF50')
                
                short_hash = tx['hash'][:8] + "..." + tx['hash'][-6:]
                short_address = address[:6] + "..." + address[-4:]
                
                self.transaction_table.setItem(row, 0, QTableWidgetItem(short_hash))
                self.transaction_table.setItem(row, 1, QTableWidgetItem(short_address))
                
                type_item = QTableWidgetItem(tx_type)
                type_item.setForeground(type_color)
                self.transaction_table.setItem(row, 2, type_item)
                
                value_item = QTableWidgetItem(f"{tx['value']:.6f}")
                value_item.setForeground(type_color)
                self.transaction_table.setItem(row, 3, value_item)
                
                self.transaction_table.setItem(row, 4, QTableWidgetItem(tx.get('token', 'BNB')))
                
                status_item = QTableWidgetItem(tx.get('status', 'pending'))
                if tx.get('status', '').lower() == 'confirmed':
                    status_item.setForeground(QColor('#4CAF50'))
                else:
                    status_item.setForeground(QColor('#FF9800'))
                self.transaction_table.setItem(row, 5, status_item)
            
            self.show_loading(False)
            logger.debug(f"Historial actualizado con {len(transactions)} transacciones")

        worker = Worker(fetch_transactions)
        worker.finished.connect(update_table)
        worker.error.connect(lambda e: self.show_loading(False))
        self.active_workers.append(worker)
        worker.start()

    def setup_send_tab(self):
        self.send_tab = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(15)
        
        form = QFormLayout()
        form.setSpacing(10)
        
        self.token_combo = QComboBox()
        self.token_combo.addItems(['BNB', 'USDT', 'USDC'])
        form.addRow("Token:", self.token_combo)
        
        self.recipient_address = QLineEdit()
        self.recipient_address.setPlaceholderText("Dirección BSC (0x...)")
        form.addRow("Para:", self.recipient_address)
        
        self.send_amount = QLineEdit()
        self.send_amount.setPlaceholderText("0.0")
        self.send_amount.setValidator(QDoubleValidator(0, 1000000, 6))
        form.addRow("Cantidad:", self.send_amount)
        
        layout.addLayout(form)
        
        fee_group = QGroupBox("Configuración de Tarifas")
        fee_layout = QVBoxLayout()
        
        self.speed_combo = QComboBox()
        self.speed_combo.addItems([
            "Económica (Baja prioridad)",
            "Estándar (Prioridad media)",
            "Rápida (Alta prioridad)",
            "Urgente (Máxima prioridad)"
        ])
        self.speed_combo.currentIndexChanged.connect(self.update_estimated_fee)
        
        fee_layout.addWidget(QLabel("Velocidad de transacción:"))
        fee_layout.addWidget(self.speed_combo)
        
        self.fee_label = QLabel("Costo estimado: ~$0.00")
        self.fee_label.setStyleSheet("color: #666; font-size: 12px;")
        fee_layout.addWidget(self.fee_label)
        
        fee_group.setLayout(fee_layout)
        layout.addWidget(fee_group)
        
        self.advanced_group = QGroupBox("Configuración Avanzada")
        self.advanced_group.setCheckable(True)
        self.advanced_group.setChecked(False)
        self.advanced_group.toggled.connect(self.on_advanced_toggled)
        advanced_layout = QFormLayout()
        
        self.gas_price_input = QLineEdit()
        self.gas_price_input.setValidator(QDoubleValidator(0.1, 1000, 1))
        self.gas_price_input.textChanged.connect(self.on_gas_price_changed)
        
        self.gas_limit_input = QLineEdit("21000")
        self.gas_limit_input.setValidator(QIntValidator(21000, 1000000))
        
        advanced_layout.addRow("Precio Gas (Gwei):", self.gas_price_input)
        advanced_layout.addRow("Límite de Gas:", self.gas_limit_input)
        self.advanced_group.setLayout(advanced_layout)
        layout.addWidget(self.advanced_group)
        
        self.send_button = QPushButton("Enviar Transacción")
        self.send_button.setStyleSheet("""
            QPushButton {
                background-color: #4e9af1;
                color: white;
                padding: 10px;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #3a7bc8;
            }
        """)
        self.send_button.clicked.connect(self.send_transaction)
        layout.addWidget(self.send_button)
        
        self.send_tab.setLayout(layout)
        self.tabs.addTab(self.send_tab, QIcon(":/icons/send.svg"), "Enviar")

    def on_advanced_toggled(self, checked):
        """Maneja el cambio en el estado del grupo avanzado"""
        if checked:
            speed_names = ['low', 'medium', 'high', 'urgent']
            speed = speed_names[self.speed_combo.currentIndex()]
            gas_params = self.current_wallet.calculate_optimal_gas(
                self.token_combo.currentText(),
                speed
            )
            self.gas_price_input.setText(str(gas_params['gas_price']))
            self.gas_limit_input.setText(str(gas_params['gas_limit']))
        self.update_estimated_fee()

    def update_estimated_fee(self):
        """Actualiza la estimación de tarifa basada en los parámetros actuales"""
        try:
            if not self.online:
                raise ConnectionError("Sin conexión")
                
            if not hasattr(self, 'current_wallet') or not self.current_wallet:
                return
                
            if self.advanced_group.isChecked():
                try:
                    gas_price = float(self.gas_price_input.text())
                    gas_limit = int(self.gas_limit_input.text())
                    speed = "Manual"
                except ValueError:
                    return
            else:
                speed_names = ['low', 'medium', 'high', 'urgent']
                speed = speed_names[self.speed_combo.currentIndex()]
                gas_params = self.current_wallet.calculate_optimal_gas(
                    self.token_combo.currentText(),
                    speed
                )
                gas_price = gas_params['gas_price']
                gas_limit = gas_params['gas_limit']
            
            fee_bnb = (gas_limit * gas_price) / 1e9
            fee_usd = fee_bnb * self.bnb_price
            
            self.fee_label.setText(
                f"Costo estimado: {fee_bnb:.6f} BNB (~${fee_usd:.2f} USD)\n"
                f"Velocidad: {speed} (~{self.get_time_estimate(gas_price)})"
            )
                
        except Exception as e:
            logger.error(f"Error actualizando fee: {str(e)}")
            self.fee_label.setText("Error calculando tarifa")
    
    def get_time_estimate(self, gas_price):
        """Estima tiempo de confirmación con base en el gas price"""
        if not hasattr(self, 'current_gas_prices'):
            return "N/A"
        
        if gas_price >= self.current_gas_prices.get('urgent', 20):
            return "< 1 minuto"
        elif gas_price >= self.current_gas_prices.get('high', 10):
            return "1-2 minutos"
        elif gas_price >= self.current_gas_prices.get('medium', 5):
            return "2-5 minutos"
        else:
            return "5+ minutos"

    def get_bnb_price(self):
        """Obtiene el precio actual de BNB en USD usando TradingView con manejo de errores"""
        if not self.online:
            raise ConnectionError("No hay conexión a internet")
        
        try:
            import requests
            from requests.exceptions import RequestException
            
            url = "https://scanner.tradingview.com/crypto/scan"
            headers = {
                "User-Agent": "Mozilla/5.0",
                "Content-Type": "application/json"
            }
            payload = {
                "filter": [{"left": "name", "operation": "equal", "right": "BNBUSDT"}],
                "options": {"lang": "en"},
                "symbols": {"query": {"types": []}, "tickers": []},
                "columns": ["close"],
                "sort": {"sortBy": "name", "sortOrder": "asc"},
                "range": [0, 1]
            }

            try:
                response = requests.post(url, json=payload, headers=headers, timeout=5)
                response.raise_for_status()
                
                data = response.json()
                if data and 'data' in data and len(data['data']) > 0:
                    return float(data['data'][0]['d'][0])
                
                raise ValueError("Datos de TradingView no válidos")
                
            except RequestException as e:
                logger.error(f"Error de red al obtener precio: {str(e)}")
                raise ConnectionError("Error al conectar con TradingView") from e
            except ValueError as e:
                logger.error(f"Datos inválidos de TradingView: {str(e)}")
                raise ValueError("No se pudo obtener el precio de BNB") from e
                
        except Exception as e:
            logger.error(f"Error inesperado en get_bnb_price: {str(e)}")
            raise

    def on_gas_price_changed(self):
        """Cuando el usuario modifica manualmente el gas price"""
        if self.advanced_group.isChecked() and self.gas_price_input.text():
            try:
                gas_price = float(self.gas_price_input.text())
                self.update_estimated_fee()
            except ValueError:
                pass

    def cleanup_workers(self):
        for worker in self.active_workers[:]:
            if worker.isFinished():
                try:
                    worker.stop()
                    worker.deleteLater()
                    self.active_workers.remove(worker)
                except Exception as e:
                    logger.error(f"Error limpiando worker: {str(e)}")

    def select_wallet(self, item):
        self.update_last_activity()
        file_path = item.data(Qt.UserRole)
        
        if file_path == self.current_file:
            return
        
        if self.current_wallet:
            self.logout()
        
        result, password = self.create_password_dialog(
            "Contraseña", 
            f"Ingrese la contraseña para {os.path.basename(file_path)}:"
        )
        
        if not result or not password:
            return
        
        self.show_loading()
        
        worker = Worker(self.wallet_manager.decrypt_wallet, file_path, password)
        worker.finished.connect(lambda w: self.on_wallet_selected(w, file_path))
        worker.error.connect(self.on_wallet_select_error)
        self.active_workers.append(worker)
        worker.start()

    def on_wallet_selected(self, wallet, file_path):
        self.show_loading(False)
        self.current_wallet = wallet
        self.current_file = file_path
        
        if file_path not in self.wallet_manager.wallet_files:
            self.wallet_manager.wallet_files.append(file_path)
            self.wallet_manager.save_wallet_files()
            self.load_wallet_list()
        
        for i in range(self.wallet_list.count()):
            item = self.wallet_list.item(i)
            if item.data(Qt.UserRole) == file_path:
                item.setSelected(True)
                break
        
        self.update_wallet_info()
        self.cleanup_workers()
        
        self.stacked_widget.setCurrentIndex(0)
    
    def on_wallet_select_error(self, error):
        logger.error(f"Error al seleccionar wallet: {error}")
        self.show_loading(False)
        QMessageBox.critical(self, "Error", f"No se pudo cargar la billetera: {error}")
        self.cleanup_workers()

    def update_wallet_info(self):
        logger.debug("Actualizando información del wallet")
        if not self.current_wallet:
            logger.debug("No hay wallet cargado, mostrando estado inicial")
            self.show_empty_state()
            return
        
        self.show_wallet_state()
        self.address_label.setText(self.current_wallet.address)
        self.generate_qr_code(self.current_wallet.address)
        
        self.show_loading()
        
        def fetch_wallet_data():
            try:
                logger.debug("Obteniendo datos del wallet")
                bnb = self.current_wallet.get_balance('BNB')
                usdt = self.current_wallet.get_balance('USDT')
                usdc = self.current_wallet.get_balance('USDC')
                txs = self.current_wallet.get_transactions()
                return {
                    'bnb': bnb,
                    'usdt': usdt,
                    'usdc': usdc,
                    'txs': txs
                }
            except Exception as e:
                logger.error(f"Error obteniendo datos: {e}")
                return None

        def update_ui(data):
            if data is None:
                QMessageBox.warning(self, "Error", "No se pudieron obtener los datos del wallet")
                return
                
            self.bnb_balance.setText(f"{data['bnb']:.6f}" if data['bnb'] is not None else "Error")
            self.usdt_balance.setText(f"{data['usdt']:.6f}" if data['usdt'] is not None else "Error")
            self.usdc_balance.setText(f"{data['usdc']:.6f}" if data['usdc'] is not None else "Error")
            
            self.transaction_table.setRowCount(len(data['txs']))
            for row, tx in enumerate(data['txs']):
                self.transaction_table.setItem(row, 0, QTableWidgetItem(tx['hash'][:16] + "..."))
                self.transaction_table.setItem(row, 1, QTableWidgetItem(tx['from']))
                self.transaction_table.setItem(row, 2, QTableWidgetItem(tx['to']))
                self.transaction_table.setItem(row, 3, QTableWidgetItem(f"{tx['value']:.6f}"))
                self.transaction_table.setItem(row, 4, QTableWidgetItem(tx.get('token', 'BNB')))
                self.transaction_table.setItem(row, 5, QTableWidgetItem(tx['status']))
            
            self.show_loading(False)

        worker = Worker(fetch_wallet_data)
        worker.finished.connect(update_ui)
        worker.error.connect(lambda e: self.show_loading(False))
        self.active_workers.append(worker)
        worker.start()

    def generate_qr_code(self, address):
        try:
            logger.debug(f"Generando QR code para dirección: {address}")
            
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_H,
                box_size=10,
                border=4,
            )
            qr.add_data(address)
            qr.make(fit=True)
            
            img = qr.make_image(
                fill_color="#4e9af1",
                back_color="#ffffff"
            )
            
            img = img.convert("RGBA")
            data = img.tobytes("raw", "RGBA")
            qimg = QImage(
                data, 
                img.size[0], 
                img.size[1], 
                QImage.Format_RGBA8888
            )
            
            pixmap = QPixmap.fromImage(qimg)
            
            final_pixmap = QPixmap(pixmap.size())
            final_pixmap.fill(Qt.transparent)
            
            painter = QPainter(final_pixmap)
            painter.setRenderHint(QPainter.Antialiasing)
            
            shadow = QPainterPath()
            shadow.addRoundedRect(QRectF(5, 5, pixmap.width(), pixmap.height()), 10, 10)
            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor(0, 0, 0, 50))
            painter.drawPath(shadow)
            
            bg_path = QPainterPath()
            bg_path.addRoundedRect(QRectF(0, 0, pixmap.width(), pixmap.height()), 10, 10)
            painter.setPen(Qt.NoPen)
            painter.setBrush(Qt.white)
            painter.drawPath(bg_path)
            
            painter.drawPixmap(0, 0, pixmap)
            painter.end()
            
            final_pixmap = final_pixmap.scaled(
                self.qr_code_label.width(),
                self.qr_code_label.height(),
                Qt.KeepAspectRatio,
                Qt.SmoothTransformation
            )
            
            self.qr_code_label.setPixmap(final_pixmap)
            logger.debug("QR code generado exitosamente con estilo mejorado")
            
        except Exception as e:
            logger.error(f"Error generando QR mejorado: {str(e)}\n{traceback.format_exc()}")
            try:
                qr = qrcode.QRCode(
                    version=1,
                    error_correction=qrcode.constants.ERROR_CORRECT_L,
                    box_size=8,
                    border=2,
                )
                qr.add_data(address)
                qr.make(fit=True)
                img = qr.make_image(fill_color="black", back_color="white")
                img_bytes = img.tobytes()
                qimage = QImage(
                    img_bytes, 
                    img.size[0], 
                    img.size[1], 
                    QImage.Format_Grayscale8
                )
                pixmap = QPixmap.fromImage(qimage)
                pixmap = pixmap.scaled(
                    self.qr_code_label.width(),
                    self.qr_code_label.height(),
                    Qt.KeepAspectRatio,
                    Qt.SmoothTransformation
                )
                self.qr_code_label.setPixmap(pixmap)
            except:
                self.qr_code_label.clear()
                self.qr_code_label.setText("Error generando QR")
                self.qr_code_label.setStyleSheet("color: red; font-weight: bold;")

    def show_loading(self, show=True):
        if show:
            self.stacked_widget.setCurrentIndex(1)
            self.loading_widget.setVisible(True)
        else:
            self.stacked_widget.setCurrentIndex(0)
            self.loading_widget.setVisible(False)
    
    def update_last_activity(self):
        self.last_activity = datetime.now()
    
    def check_session(self):
        if self.current_wallet and (datetime.now() - self.last_activity).total_seconds() > SESSION_TIMEOUT * 60:
            logger.info("Sesión expirada por inactividad")
            QMessageBox.information(self, "Sesión expirada", "Su sesión ha expirado por inactividad.")
            self.logout()
    
    def logout(self):
        logger.debug("Cerrando sesión")
        self.current_wallet = None
        self.current_file = None
        self.update_wallet_info()
        self.last_activity = datetime.now()
        
    def load_wallet_list(self):
        self.wallet_list.clear()
        for wallet_file in self.wallet_manager.wallet_files:
            item = QListWidgetItem(os.path.basename(wallet_file))
            item.setData(Qt.UserRole, wallet_file)
            item.setIcon(self.style().standardIcon(QStyle.SP_FileLinkIcon))
            self.wallet_list.addItem(item)
            
    def create_password_dialog(self, title, message):
        logger.debug(f"Creando diálogo de contraseña: {title}")
        dialog = QDialog(self)
        dialog.setWindowTitle(title)
        dialog.setModal(True)
        dialog.setMinimumWidth(300)
        
        layout = QVBoxLayout(dialog)
        
        label = QLabel(message)
        layout.addWidget(label)
        
        password_edit = QLineEdit()
        password_edit.setEchoMode(QLineEdit.Password)
        layout.addWidget(password_edit)
        
        toggle_container = QWidget()
        toggle_layout = QHBoxLayout(toggle_container)
        toggle_layout.setContentsMargins(0, 0, 0, 0)
        
        toggle_button = QPushButton("Mostrar")
        toggle_button.setCheckable(True)
        toggle_button.setStyleSheet("QPushButton {padding: 3px;}")
        
        def toggle_password(checked):
            if checked:
                password_edit.setEchoMode(QLineEdit.Normal)
                toggle_button.setText("Ocultar")
            else:
                password_edit.setEchoMode(QLineEdit.Password)
                toggle_button.setText("Mostrar")
        
        toggle_button.clicked.connect(toggle_password)
        toggle_layout.addWidget(toggle_button, 0, Qt.AlignRight)
        layout.addWidget(toggle_container)
        
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(dialog.accept)
        button_box.rejected.connect(dialog.reject)
        layout.addWidget(button_box)
        
        result = dialog.exec_()
        
        return (result == QDialog.Accepted, password_edit.text())

    def create_new_wallet(self):
        self.update_last_activity()
        logger.debug("Iniciando creación de nuevo wallet")
        
        result, password = self.create_password_dialog(
            "Contraseña", 
            "Ingrese una contraseña segura para cifrar la billetera:"
        )
        
        if not result or not password:
            logger.debug("Creación de wallet cancelada por el usuario")
            return
        
        if len(password) < 8:
            self.show_password_error("La contraseña debe tener al menos 8 caracteres.")
            return
        
        if not any(c.isupper() for c in password):
            self.show_password_error("La contraseña debe contener al menos una mayúscula.")
            return
        
        if not any(c.isdigit() for c in password):
            self.show_password_error("La contraseña debe contener al menos un número.")
            return
        
        result, confirm_password = self.create_password_dialog(
            "Confirmar Contraseña", 
            "Vuelva a ingresar la contraseña para confirmar:"
        )
        
        if not result or password != confirm_password:
            self.show_password_error("Las contraseñas no coinciden.")
            return
        
        wallet = self.wallet_manager.create_wallet()
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Guardar Billetera", 
            f"SolidWallet_{wallet.address[:6]}.cwallet", 
            "Billetera Cripto (*.cwallet)"
        )
        
        if not file_path:
            logger.debug("Guardado de wallet cancelado por el usuario")
            return
        
        if not file_path.endswith('.cwallet'):
            file_path += '.cwallet'
        
        self.show_loading()
        
        worker = Worker(self.wallet_manager.encrypt_wallet, wallet, password, file_path)
        worker.finished.connect(lambda f: self.on_wallet_created(wallet, f))
        worker.error.connect(self.on_wallet_create_error)
        self.active_workers.append(worker)
        logger.debug(f"Iniciando worker para cifrar wallet (ID: {id(worker)})")
        worker.start()

    def on_wallet_created(self, wallet, file_path):
        logger.debug(f"Wallet creado exitosamente: {file_path}")
        self.show_loading(False)
        self.load_wallet_list()
        reply = QMessageBox.question(
            self, 'Billetera Creada', 
            '¿Desea cargar la billetera recién creada?',
            QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes
        )
        if reply == QMessageBox.Yes:
            logger.debug("Usuario eligió cargar el wallet recién creado")
            self.current_wallet = wallet
            self.current_file = file_path
            self.update_wallet_info()
        QMessageBox.information(self, "Éxito", "Billetera creada y guardada exitosamente!")
        self.cleanup_workers()

    def on_wallet_create_error(self, error):
        logger.error(f"Error al crear wallet: {error}")
        self.show_loading(False)
        QMessageBox.critical(self, "Error", f"No se pudo guardar la billetera: {error}")
        self.cleanup_workers()

    def show_password_error(self, message):
        logger.warning(f"Error en contraseña: {message}")
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Warning)
        msg.setWindowTitle("Error en Contraseña")
        msg.setText(message)
        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec_()
    
    def load_wallet(self):
        self.update_last_activity()
        logger.debug("Iniciando carga de wallet")
        
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Abrir Billetera", 
            "", "Billetera Cripto (*.cwallet)"
        )
        
        if not file_path:
            logger.debug("Carga de wallet cancelada por el usuario")
            return
        
        result, password = self.create_password_dialog(
            "Contraseña", 
            f"Ingrese la contraseña para {os.path.basename(file_path)}:"
        )
        
        if not result or not password:
            logger.debug("Usuario canceló ingreso de contraseña")
            return
        
        self.show_loading()
        
        worker = Worker(self.wallet_manager.decrypt_wallet, file_path, password)
        worker.finished.connect(lambda w: self.on_wallet_loaded(w, file_path))
        worker.error.connect(self.on_wallet_load_error)
        self.active_workers.append(worker)
        logger.debug(f"Iniciando worker para descifrar wallet (ID: {id(worker)})")
        worker.start()

    def on_wallet_loaded(self, wallet, file_path):
        logger.debug(f"Wallet cargado exitosamente: {file_path}")
        self.show_loading(False)
        self.current_wallet = wallet
        self.current_file = file_path
        
        if file_path not in self.wallet_manager.wallet_files:
            self.wallet_manager.wallet_files.append(file_path)
            self.wallet_manager.save_wallet_files()
            self.load_wallet_list()
        
        self.update_wallet_info()
        self.cleanup_workers()
    
    def on_wallet_load_error(self, error):
        logger.error(f"Error al cargar wallet: {error}")
        self.show_loading(False)
        QMessageBox.critical(self, "Error", f"No se pudo cargar la billetera: {error}")
        self.cleanup_workers()

    def show_connectivity_error(self):
        """Muestra error de conectividad"""
        QMessageBox.critical(
            self, 
            "Sin conexión", 
            "No se puede conectar a internet. Esta operación requiere conexión a la red."
        )

    def show_error_message(self, message):
        """Muestra mensajes de error con íconos más grandes"""
        msg = QMessageBox(self)
        
        warning_icon = QIcon(":/icons/warning.svg")
        msg.setIconPixmap(warning_icon.pixmap(QSize(48, 48)))
        
        msg.setWindowTitle("Error")
        msg.setText(message)
        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec_()
        
    def send_transaction(self):
        """Método para enviar transacción con validación de conectividad"""
        self.update_last_activity()
        
        if not self.online:
            self.show_connectivity_error()
            return

        if not self.current_wallet:
            QMessageBox.critical(self, "Error", "No hay billetera cargada")
            return
        
        recipient = self.recipient_address.text().strip()
        amount_text = self.send_amount.text().strip()
        token = self.token_combo.currentText()
        
        if not recipient or not amount_text:
            QMessageBox.warning(self, "Advertencia", "Complete todos los campos requeridos.")
            return
        
        try:
            amount = float(amount_text)
            if amount <= 0:
                raise ValueError("La cantidad debe ser positiva")
        except ValueError:
            QMessageBox.warning(self, "Advertencia", "Cantidad inválida")
            return
        
        if not Web3.is_address(recipient):
            QMessageBox.warning(self, "Advertencia", "Dirección inválida")
            return
        
        try:
            if self.advanced_group.isChecked():
                gas_price = float(self.gas_price_input.text())
                gas_limit = int(self.gas_limit_input.text())
            else:
                speed_names = ['low', 'medium', 'high', 'urgent']
                speed = speed_names[self.speed_combo.currentIndex()]
                gas_params = self.current_wallet.calculate_optimal_gas(token, speed)
                gas_price = gas_params['gas_price']
                gas_limit = gas_params['gas_limit']
        except ValueError:
            QMessageBox.warning(self, "Advertencia", "Configuración de gas inválida")
            return
        
        fee_bnb = (gas_limit * gas_price) / 1e9
        fee_usd = fee_bnb * self.bnb_price
        
        confirm = QMessageBox.question(
            self, "Confirmar", 
            f"¿Enviar {amount:.6f} {token} a {recipient[:10]}...?\n\n"
            f"Fee estimado: {fee_bnb:.6f} BNB (~${fee_usd:.2f} USD)\n"
            f"Tiempo estimado: {self.get_time_estimate(gas_price)}",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if confirm != QMessageBox.Yes:
            return
        
        self.show_loading()
        
        worker = Worker(
            lambda: self.current_wallet.send_transaction(
                recipient,
                amount,
                token,
                gas_price=gas_price,
                gas_limit=gas_limit
            )
        )
        worker.finished.connect(self.on_transaction_sent)
        worker.error.connect(self.on_transaction_error)
        self.active_workers.append(worker)
        worker.start()

    def on_transaction_sent(self, tx_hash):
        """Maneja transacción exitosa"""
        self.show_loading(False)
        if not self.online:
            QMessageBox.warning(
                self, 
                "Transacción enviada pero sin conexión",
                f"Transacción enviada con hash: {tx_hash}\n\n"
                "Pero no hay conexión a internet para confirmar el estado."
            )
        else:
            QMessageBox.information(
                self, 
                "Éxito", 
                f"Transacción enviada!\nHash: {tx_hash}\n\n"
                "Puedes verificar el estado en BscScan."
            )
        self.update_wallet_info()

    def on_transaction_error(self, error):
        """Maneja errores en transacción"""
        self.show_loading(False)
        
        if isinstance(error, ConnectionError):
            self.show_connectivity_error()
        else:
            error_msg = str(error)
            if "insufficient funds" in error_msg.lower():
                error_msg = "Fondos insuficientes para cubrir el valor + fee de gas"
            elif "gas" in error_msg.lower():
                error_msg = "Error en configuración de gas: " + error_msg
            
            QMessageBox.critical(
                self, 
                "Error en transacción", 
                f"No se pudo enviar la transacción:\n\n{error_msg}"
            )

if __name__ == "__main__":
    import sys
    
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    # Precargar recursos para mejor rendimiento
    QIcon(":/icons/solidwallet.png")
    QIcon(":/icons/info.svg")
    QIcon(":/icons/history.svg")
    QIcon(":/icons/send.svg")
    
    window = SolidWalletGUI()
    window.show()
    
    try:
        sys.exit(app.exec_())
    except Exception as e:
        logger.critical(f"Error fatal en la aplicación: {e}")
        raise