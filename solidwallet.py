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
                            QFrame)
from PyQt5.QtGui import (QPixmap, QImage, QIcon, QPainter, QBrush, QPen, QColor,
                        QFont, QPainterPath, QDoubleValidator, QIntValidator, QRadialGradient, QConicalGradient)
from PyQt5.QtCore import Qt, QTimer, QSize, QFile, QIODevice, pyqtSignal, QThread, QRectF, QPropertyAnimation, QEasingCurve, QPoint
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
    
    def send_transaction(self, to_address, amount, token_symbol='BNB', gas_limit=21000):
        logger.debug(f"Preparando transacción de {amount} {token_symbol} a {to_address}")
        try:
            to_address = Web3.to_checksum_address(to_address)
            
            if token_symbol == 'BNB':
                tx = {
                    'from': self.address,
                    'to': to_address,
                    'value': self.web3.to_wei(amount, 'ether'),
                    'gas': gas_limit,
                    'gasPrice': self.web3.eth.gas_price,
                    'nonce': self.web3.eth.get_transaction_count(self.address),
                }
                
                signed_tx = self.web3.eth.account.sign_transaction(tx, self.private_key)
                tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
                logger.debug(f"Transacción BNB enviada: {tx_hash.hex()}")
                return tx_hash.hex()
            else:
                contract = self.web3.eth.contract(
                    address=TOKEN_CONTRACTS[token_symbol],
                    abi=self._get_erc20_abi()
                )
                
                tx = contract.functions.transfer(
                    to_address,
                    int(amount * (10 ** TOKEN_DECIMALS[token_symbol]))
                ).build_transaction({
                    'from': self.address,
                    'gas': gas_limit,
                    'gasPrice': self.web3.eth.gas_price,
                    'nonce': self.web3.eth.get_transaction_count(self.address),
                })
                
                signed_tx = self.web3.eth.account.sign_transaction(tx, self.private_key)
                tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
                logger.debug(f"Transacción {token_symbol} enviada: {tx_hash.hex()}")
                return tx_hash.hex()
        except Exception as e:
            logger.error(f"Error enviando transacción: {str(e)}")
            raise
    
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
        
        self.setWindowTitle("SolidWallet - BSC Wallet")
        self.resize(1000, 700)
        self.setMinimumSize(900, 600)
        self.setWindowIcon(self.create_app_icon())
        self.setStyleSheet(self.get_stylesheet())
        
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
        
        # Mostrar vista inicial
        if self.wallet_manager.wallet_files:
            self.stacked_widget.setCurrentIndex(0)
            self.show_empty_state()
        else:
            self.stacked_widget.setCurrentIndex(2)

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

        # Configuración perfecta para la imagen
        icon_label = QLabel()
        icon_label.setAlignment(Qt.AlignCenter)
        icon_label.setStyleSheet("background: transparent; padding: 0; margin: 0;")
        
        # 1. Cargar la imagen original
        original_pixmap = QPixmap(":/icons/no_wallet.png")
        
        # 2. Definir tamaño máximo deseado (ajusta según necesites)
        max_size = 200  # Para una imagen cuadrada
        
        # 3. Escalado inteligente que mantiene la imagen completa
        if original_pixmap.width() > original_pixmap.height():
            # Imagen horizontal
            scaled_pixmap = original_pixmap.scaledToWidth(max_size, Qt.SmoothTransformation)
        else:
            # Imagen vertical o cuadrada
            scaled_pixmap = original_pixmap.scaledToHeight(max_size, Qt.SmoothTransformation)
        
        # 4. Aplicar la imagen escalada
        icon_label.setPixmap(scaled_pixmap)
        
        # 5. Opcional: Centrar en un área cuadrada si lo prefieres
        icon_container = QWidget()
        icon_container.setFixedSize(max_size, max_size)
        icon_layout = QHBoxLayout(icon_container)
        icon_layout.setContentsMargins(0, 0, 0, 0)
        icon_layout.addWidget(icon_label)

        # Resto de la interfaz
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
        
        # Tabs
        self.tabs = QTabWidget()
        self.setup_info_tab()
        self.setup_tx_tab()
        self.setup_send_tab()
        
        # Botón desconectar
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
        
        # Detener todos los workers activos
        logger.debug(f"Deteniendo {len(self.active_workers)} workers activos")
        for worker in self.active_workers:
            try:
                logger.debug(f"Deteniendo worker {id(worker)}")
                worker.stop()
            except Exception as e:
                logger.error(f"Error deteniendo worker: {str(e)}\n{traceback.format_exc()}")
        
        # Limpiar todos los workers
        self.cleanup_workers()
        
        # Verificar si quedó algún worker activo
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
        
        # Logo más grande (250x250)
        logo_label = QLabel()
        pixmap = QPixmap(":/icons/solidwallet.png").scaled(250, 250, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        logo_label.setPixmap(pixmap)
        logo_label.setAlignment(Qt.AlignCenter)
        
        # Título con sombra
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
        
        # Efecto de sombra para el título
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(10)
        shadow.setColor(QColor(0, 0, 0, 80))
        shadow.setOffset(2, 2)
        title.setGraphicsEffect(shadow)
        title.setAlignment(Qt.AlignCenter)
        
        # Subtítulo con estilo mejorado
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
        
        # Contenedor de botones con sombra
        btn_container = QWidget()
        btn_container.setStyleSheet("""
            QWidget {
                background-color: #ffffff;
                border-radius: 10px;
                padding: 20px;
            }
        """)
        
        # Efecto de sombra para el contenedor
        container_shadow = QGraphicsDropShadowEffect()
        container_shadow.setBlurRadius(15)
        container_shadow.setColor(QColor(0, 0, 0, 30))
        container_shadow.setOffset(0, 5)
        btn_container.setGraphicsEffect(container_shadow)
        
        btn_layout = QVBoxLayout()
        btn_layout.setContentsMargins(50, 20, 50, 20)
        btn_layout.setSpacing(20)
        
        # Botón de crear con icono más grande
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
        
        # Botón de cargar con icono más grande
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
        
        # Título con estilo
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
        
        # Contenedor con scroll para la lista de wallets
        scroll_container = QWidget()
        scroll_layout = QVBoxLayout(scroll_container)
        scroll_layout.setContentsMargins(0, 0, 0, 0)
        
        # Lista de wallets con scroll
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
        
        # Scroll Area
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
        left_layout.addWidget(scroll_container, 1)  # Ocupa el espacio disponible
        
        # Botones
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

    def setup_right_panel(self):
        # Panel derecho
        right_panel = QVBoxLayout()
        right_panel.setSpacing(15)
        
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.setStyleSheet("""
            QTabBar::tab {
                padding: 8px 15px;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
            }
            QTabBar::tab:selected {
                background: #ffffff;
                border-bottom: 3px solid #4e9af1;
            }
        """)
        
        # --------------------------------------------
        # Pestaña de Información
        # --------------------------------------------
        info_tab = QWidget()
        info_layout = QVBoxLayout()
        info_layout.setContentsMargins(15, 15, 15, 15)
        info_layout.setSpacing(15)
        
        # Sección de dirección
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
        
        # Sección de balances
        balances_group = QGroupBox("Balances")
        balances_layout = QFormLayout()
        
        self.bnb_balance = QLabel("0.0")
        self.usdt_balance = QLabel("0.0")
        self.usdc_balance = QLabel("0.0")
        
        balances_layout.addRow(QLabel("BNB:"), self.bnb_balance)
        balances_layout.addRow(QLabel("USDT:"), self.usdt_balance)
        balances_layout.addRow(QLabel("USDC:"), self.usdc_balance)
        balances_group.setLayout(balances_layout)
        
        # Sección de QR Code
        qr_group = QGroupBox("Código QR para recibir")
        qr_layout = QVBoxLayout()
        
        self.qr_code_label = QLabel()
        self.qr_code_label.setAlignment(Qt.AlignCenter)
        self.qr_code_label.setFixedSize(250, 250)
        self.qr_code_label.setStyleSheet("""
            QLabel {
                background-color: white;
                border: 1px solid #dee2e6;
                border-radius: 5px;
                padding: 10px;
            }
        """)
        
        qr_layout.addWidget(self.qr_code_label, 0, Qt.AlignCenter)
        qr_group.setLayout(qr_layout)
        
        # Agregar widgets a la pestaña de información
        info_layout.addWidget(address_group)
        info_layout.addWidget(balances_group)
        info_layout.addWidget(qr_group)
        info_layout.addStretch()
        info_tab.setLayout(info_layout)
        
        # --------------------------------------------
        # Pestaña de Transacciones
        # --------------------------------------------
        tx_tab = QWidget()
        tx_layout = QVBoxLayout()
        tx_layout.setContentsMargins(5, 5, 5, 5)
        
        self.transaction_table = QTableWidget()
        self.transaction_table.setColumnCount(6)
        self.transaction_table.setHorizontalHeaderLabels(["Hash", "De", "Para", "Valor", "Token", "Estado"])
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
        tx_tab.setLayout(tx_layout)
        
        # --------------------------------------------
        # Pestaña de Enviar
        # --------------------------------------------
        send_tab = QWidget()
        send_layout = QVBoxLayout()
        send_layout.setContentsMargins(15, 15, 15, 15)
        send_layout.setSpacing(15)
        
        send_form = QFormLayout()
        send_form.setSpacing(10)
        
        self.token_combo = QComboBox()
        self.token_combo.addItems(['BNB', 'USDT', 'USDC'])
        self.token_combo.setStyleSheet("QComboBox { padding: 5px; }")
        
        self.recipient_address = QLineEdit()
        self.recipient_address.setPlaceholderText("Dirección del destinatario")
        
        self.send_amount = QLineEdit()
        self.send_amount.setPlaceholderText("0.0")
        self.send_amount.setValidator(QDoubleValidator(0, 1000000, 6))
        
        self.gas_limit = QLineEdit("21000")
        self.gas_limit.setValidator(QIntValidator(21000, 1000000))
        
        btn_send = QPushButton("Enviar Transacción")
        btn_send.setIcon(self.style().standardIcon(QStyle.SP_ArrowRight))
        btn_send.setStyleSheet("""
            QPushButton {
                padding: 8px 16px;
                font-weight: bold;
            }
        """)
        btn_send.clicked.connect(self.send_transaction)
        
        send_form.addRow("Token:", self.token_combo)
        send_form.addRow("Destinatario:", self.recipient_address)
        send_form.addRow("Cantidad:", self.send_amount)
        send_form.addRow("Límite de Gas:", self.gas_limit)
        send_layout.addLayout(send_form)
        send_layout.addWidget(btn_send, 0, Qt.AlignRight)
        send_layout.addStretch()
        send_tab.setLayout(send_layout)
        
        # Agregar pestañas al widget principal
        self.tabs.addTab(info_tab, QIcon(":/icons/info.svg"), "Información")
        self.tabs.addTab(tx_tab, QIcon(":/icons/history.svg"), "Transacciones")
        self.tabs.addTab(send_tab, QIcon(":/icons/send.svg"), "Enviar")
        
        right_panel.addWidget(self.tabs)
        self.main_layout.addLayout(right_panel, 1)

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
        
        # Contenedor para el botón de mostrar/ocultar
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
        
        # Botones de aceptar/cancelar
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(dialog.accept)
        button_box.rejected.connect(dialog.reject)
        layout.addWidget(button_box)
        
        result = dialog.exec_()
        
        return (result == QDialog.Accepted, password_edit.text())

    def create_new_wallet(self):
        self.update_last_activity()
        logger.debug("Iniciando creación de nuevo wallet")
        
        # Paso 1: Pedir contraseña
        result, password = self.create_password_dialog(
            "Contraseña", 
            "Ingrese una contraseña segura para cifrar la billetera:"
        )
        
        if not result or not password:
            logger.debug("Creación de wallet cancelada por el usuario")
            return
        
        # Validar contraseña segura
        if len(password) < 8:
            self.show_password_error("La contraseña debe tener al menos 8 caracteres.")
            return
        
        if not any(c.isupper() for c in password):
            self.show_password_error("La contraseña debe contener al menos una mayúscula.")
            return
        
        if not any(c.isdigit() for c in password):
            self.show_password_error("La contraseña debe contener al menos un número.")
            return
        
        # Paso 2: Confirmar contraseña
        result, confirm_password = self.create_password_dialog(
            "Confirmar Contraseña", 
            "Vuelva a ingresar la contraseña para confirmar:"
        )
        
        if not result or password != confirm_password:
            self.show_password_error("Las contraseñas no coinciden.")
            return
        
        # Crear wallet
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
        
        # Eliminamos la verificación de wallet_files para permitir cargar cualquier archivo
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
        
        # Si el archivo no estaba en la lista, agregarlo
        if file_path not in self.wallet_manager.wallet_files:
            self.wallet_manager.wallet_files.append(file_path)
            self.wallet_manager.save_wallet_files()
            self.load_wallet_list()
        
        self.update_wallet_info()
        self.cleanup_workers()
    
    def on_wallet_load_error(self, error, show_main=False):
        logger.error(f"Error al cargar wallet: {error}")
        self.show_loading(False)
        QMessageBox.critical(self, "Error", f"No se pudo cargar la billetera: {error}")
        
        if show_main:
            self.stacked_widget.setCurrentIndex(0)
            self.update_wallet_info()
        
        self.cleanup_workers()
    

    def setup_info_tab(self):
        """Configura la pestaña de información del wallet"""
        self.info_tab = QWidget()
        info_layout = QVBoxLayout()
        info_layout.setContentsMargins(15, 15, 15, 15)
        info_layout.setSpacing(15)
        
        # Sección de dirección
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
        
        # Sección de balances
        balances_group = QGroupBox("Balances")
        balances_layout = QFormLayout()
        
        self.bnb_balance = QLabel("0.0")
        self.usdt_balance = QLabel("0.0")
        self.usdc_balance = QLabel("0.0")
        
        # Estilo para los balances
        balance_style = "font-weight: bold; font-size: 14px;"
        self.bnb_balance.setStyleSheet(balance_style)
        self.usdt_balance.setStyleSheet(balance_style)
        self.usdc_balance.setStyleSheet(balance_style)
        
        balances_layout.addRow(QLabel("BNB:"), self.bnb_balance)
        balances_layout.addRow(QLabel("USDT:"), self.usdt_balance)
        balances_layout.addRow(QLabel("USDC:"), self.usdc_balance)
        balances_group.setLayout(balances_layout)
        
        # Sección de QR Code con margen inferior
        qr_group = QGroupBox("Código QR para recibir")
        qr_layout = QVBoxLayout()
        qr_layout.setContentsMargins(0, 0, 0, 20)  # Margen inferior de 20px
        
        self.qr_code_label = QLabel()
        self.qr_code_label.setAlignment(Qt.AlignCenter)
        self.qr_code_label.setFixedSize(250, 250)
        self.qr_code_label.setStyleSheet("""
            QLabel {
                background-color: white;
                border: 1px solid #dee2e6;
                border-radius: 5px;
                padding: 10px;
                margin-bottom: 20px;  /* Margen adicional */
            }
        """)
        
        qr_layout.addWidget(self.qr_code_label, 0, Qt.AlignCenter)
        qr_group.setLayout(qr_layout)
        
        # Agregar widgets a la pestaña de información
        info_layout.addWidget(address_group)
        info_layout.addWidget(balances_group)
        info_layout.addWidget(qr_group)
        info_layout.addStretch()
        self.info_tab.setLayout(info_layout)
        
        # Agregar la pestaña al tab widget
        self.tabs.addTab(self.info_tab, QIcon(":/icons/info.svg"), "Información")
        
    def setup_tx_tab(self):
        """Configura la pestaña de historial de transacciones"""
        self.tx_tab = QWidget()
        tx_layout = QVBoxLayout()
        tx_layout.setContentsMargins(5, 5, 5, 5)
        
        # Filtro por moneda
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filtrar por moneda:"))
        
        self.tx_filter_combo = QComboBox()
        self.tx_filter_combo.addItems(["Todas", "BNB", "USDT", "USDC"])
        self.tx_filter_combo.currentIndexChanged.connect(self.update_transaction_history)
        filter_layout.addWidget(self.tx_filter_combo)
        filter_layout.addStretch()
        
        tx_layout.addLayout(filter_layout)
        
        # Tabla de transacciones
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
        
        # Agregar la pestaña al tab widget con su icono
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
                # Obtener transacciones del wallet
                transactions = self.current_wallet.get_transactions()
                
                # Aplicar filtro si está seleccionado
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
                # Determinar tipo de transacción (Enviado/Recibido)
                if tx['from'].lower() == self.current_wallet.address.lower():
                    tx_type = "Enviado"
                    address = tx['to']
                    type_color = QColor('#f44336')  # Rojo
                else:
                    tx_type = "Recibido"
                    address = tx['from']
                    type_color = QColor('#4CAF50')  # Verde
                
                # Acortar hash y dirección para mejor visualización
                short_hash = tx['hash'][:8] + "..." + tx['hash'][-6:]
                short_address = address[:6] + "..." + address[-4:]
                
                # Crear items para la tabla
                self.transaction_table.setItem(row, 0, QTableWidgetItem(short_hash))
                self.transaction_table.setItem(row, 1, QTableWidgetItem(short_address))
                
                type_item = QTableWidgetItem(tx_type)
                type_item.setForeground(type_color)
                self.transaction_table.setItem(row, 2, type_item)
                
                value_item = QTableWidgetItem(f"{tx['value']:.6f}")
                value_item.setForeground(type_color)
                self.transaction_table.setItem(row, 3, value_item)
                
                self.transaction_table.setItem(row, 4, QTableWidgetItem(tx.get('token', 'BNB')))
                
                # Estado con color según confirmación
                status_item = QTableWidgetItem(tx.get('status', 'pending'))
                if tx.get('status', '').lower() == 'confirmed':
                    status_item.setForeground(QColor('#4CAF50'))  # Verde
                else:
                    status_item.setForeground(QColor('#FF9800'))  # Amarillo/naranja
                self.transaction_table.setItem(row, 5, status_item)
            
            self.show_loading(False)
            logger.debug(f"Historial actualizado con {len(transactions)} transacciones")

        # Usar Worker para la operación en segundo plano
        worker = Worker(fetch_transactions)
        worker.finished.connect(update_table)
        worker.error.connect(lambda e: self.show_loading(False))
        self.active_workers.append(worker)
        worker.start()

    def setup_send_tab(self):
        """Configura la pestaña para enviar transacciones"""
        self.send_tab = QWidget()
        send_layout = QVBoxLayout()
        send_layout.setContentsMargins(20, 20, 20, 20)
        send_layout.setSpacing(15)

        # Grupo para el formulario de envío
        send_group = QGroupBox("Enviar Fondos")
        send_group.setStyleSheet("QGroupBox { font-weight: bold; }")
        form_layout = QFormLayout()
        form_layout.setSpacing(10)

        # Selector de token
        self.token_combo = QComboBox()
        self.token_combo.addItems(['BNB', 'USDT', 'USDC'])
        self.token_combo.setStyleSheet("""
            QComboBox {
                padding: 8px;
                border: 1px solid #ddd;
                border-radius: 4px;
            }
        """)

        # Campo de dirección destino
        self.recipient_address = QLineEdit()
        self.recipient_address.setPlaceholderText("Dirección BSC del destinatario")
        self.recipient_address.setStyleSheet("""
            QLineEdit {
                padding: 8px;
                border: 1px solid #ddd;
                border-radius: 4px;
            }
        """)

        # Campo de cantidad
        self.send_amount = QLineEdit()
        self.send_amount.setPlaceholderText("0.0")
        self.send_amount.setValidator(QDoubleValidator(0, 1000000, 6))
        self.send_amount.setStyleSheet("""
            QLineEdit {
                padding: 8px;
                border: 1px solid #ddd;
                border-radius: 4px;
            }
        """)

        # Configuración avanzada (colapsable)
        self.advanced_group = QGroupBox("Configuración Avanzada")
        self.advanced_group.setCheckable(True)
        self.advanced_group.setChecked(False)
        self.advanced_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #ddd;
                border-radius: 4px;
                margin-top: 10px;
            }
            QGroupBox::indicator {
                width: 16px;
                height: 16px;
            }
        """)
        
        advanced_layout = QFormLayout()
        
        # Límite de gas
        self.gas_limit = QLineEdit("21000")
        self.gas_limit.setValidator(QIntValidator(21000, 1000000))
        self.gas_limit.setStyleSheet("""
            QLineEdit {
                padding: 8px;
                border: 1px solid #ddd;
                border-radius: 4px;
            }
        """)
        
        advanced_layout.addRow("Límite de Gas:", self.gas_limit)
        self.advanced_group.setLayout(advanced_layout)

        # Botón de envío
        self.send_button = QPushButton("Enviar Transacción")
        self.send_button.setIcon(QIcon(":/icons/send.svg"))
        self.send_button.setStyleSheet("""
            QPushButton {
                background-color: #4e9af1;
                color: white;
                padding: 10px 20px;
                border-radius: 5px;
                font-weight: bold;
                min-width: 200px;
            }
            QPushButton:hover {
                background-color: #3a7bc8;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
        """)
        self.send_button.clicked.connect(self.send_transaction)

        # Agregar elementos al formulario
        form_layout.addRow("Token:", self.token_combo)
        form_layout.addRow("Destinatario:", self.recipient_address)
        form_layout.addRow("Cantidad:", self.send_amount)
        
        # Agregar elementos al layout principal
        send_group.setLayout(form_layout)
        send_layout.addWidget(send_group)
        send_layout.addWidget(self.advanced_group)
        send_layout.addWidget(self.send_button, 0, Qt.AlignCenter)
        send_layout.addStretch()

        self.send_tab.setLayout(send_layout)
        
        # Agregar la pestaña al tab widget
        self.tabs.addTab(self.send_tab, QIcon(":/icons/send.svg"), "Enviar")
        
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
        
        # Desconectar primero si hay una wallet conectada
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
        
        # Actualizar lista si es necesario
        if file_path not in self.wallet_manager.wallet_files:
            self.wallet_manager.wallet_files.append(file_path)
            self.wallet_manager.save_wallet_files()
            self.load_wallet_list()
        
        # Resaltar el wallet seleccionado en la lista
        for i in range(self.wallet_list.count()):
            item = self.wallet_list.item(i)
            if item.data(Qt.UserRole) == file_path:
                item.setSelected(True)
                break
        
        # Forzar la actualización de la UI
        self.update_wallet_info()
        self.cleanup_workers()
        
        # Cambiar a la vista principal
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
        
        # Mostrar la interfaz de wallet conectado
        self.show_wallet_state()
        
        # Actualizar dirección
        self.address_label.setText(self.current_wallet.address)
        
        # Generar QR code
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
                
            # Actualizar balances
            self.bnb_balance.setText(f"{data['bnb']:.6f}" if data['bnb'] is not None else "Error")
            self.usdt_balance.setText(f"{data['usdt']:.6f}" if data['usdt'] is not None else "Error")
            self.usdc_balance.setText(f"{data['usdc']:.6f}" if data['usdc'] is not None else "Error")
            
            # Actualizar transacciones
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
            
            # 1. Configuración del QR
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_H,
                box_size=10,
                border=4,
            )
            qr.add_data(address)
            qr.make(fit=True)
            
            # 2. Crear imagen PIL
            img = qr.make_image(
                fill_color="#4e9af1",  # Color azul que coincide con el tema
                back_color="#ffffff"   # Fondo blanco
            )
            
            # 3. Convertir PIL Image a QImage
            img = img.convert("RGBA")
            data = img.tobytes("raw", "RGBA")
            qimg = QImage(
                data, 
                img.size[0], 
                img.size[1], 
                QImage.Format_RGBA8888
            )
            
            # 4. Crear QPixmap y escalar
            pixmap = QPixmap.fromImage(qimg)
            
            # 5. Aplicar efectos visuales
            final_pixmap = QPixmap(pixmap.size())
            final_pixmap.fill(Qt.transparent)
            
            painter = QPainter(final_pixmap)
            painter.setRenderHint(QPainter.Antialiasing)
            
            # Dibujar sombra
            shadow = QPainterPath()
            shadow.addRoundedRect(QRectF(5, 5, pixmap.width(), pixmap.height()), 10, 10)
            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor(0, 0, 0, 50))
            painter.drawPath(shadow)
            
            # Dibujar fondo blanco redondeado
            bg_path = QPainterPath()
            bg_path.addRoundedRect(QRectF(0, 0, pixmap.width(), pixmap.height()), 10, 10)
            painter.setPen(Qt.NoPen)
            painter.setBrush(Qt.white)
            painter.drawPath(bg_path)
            
            # Dibujar el QR
            painter.drawPixmap(0, 0, pixmap)
            painter.end()
            
            # 6. Escalar manteniendo calidad
            final_pixmap = final_pixmap.scaled(
                self.qr_code_label.width(),
                self.qr_code_label.height(),
                Qt.KeepAspectRatio,
                Qt.SmoothTransformation
            )
            
            # 7. Mostrar en el label
            self.qr_code_label.setPixmap(final_pixmap)
            logger.debug("QR code generado exitosamente con estilo mejorado")
            
        except Exception as e:
            logger.error(f"Error generando QR mejorado: {str(e)}\n{traceback.format_exc()}")
            # Fallback al método simple si hay error
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

    def showEvent(self, event):
        """Evento que se dispara cuando la ventana se muestra"""
        super().showEvent(event)
        pass

    
    def send_transaction(self):
        self.update_last_activity()
        logger.debug("Preparando envío de transacción")
        
        if not self.current_wallet:
            QMessageBox.warning(self, "Advertencia", "No hay billetera cargada.")
            return
        
        recipient = self.recipient_address.text().strip()
        amount_text = self.send_amount.text().strip()
        token = self.token_combo.currentText()
        gas_limit_text = self.gas_limit.text().strip()
        
        if not recipient or not amount_text or not gas_limit_text:
            QMessageBox.warning(self, "Advertencia", "Por favor complete todos los campos.")
            return
        
        try:
            amount = float(amount_text)
            gas_limit = int(gas_limit_text)
            
            if amount <= 0 or gas_limit <= 0:
                raise ValueError("Valores deben ser positivos")
        except ValueError as e:
            QMessageBox.warning(self, "Advertencia", f"Dato inválido: {str(e)}")
            return
        
        if not Web3.is_address(recipient):
            QMessageBox.warning(self, "Advertencia", "Dirección inválida")
            return
        
        recipient = Web3.to_checksum_address(recipient)
        
        confirm = QMessageBox.question(
            self, "Confirmar", 
            f"¿Enviar {amount:.6f} {token} a {recipient[:10]}...?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if confirm != QMessageBox.Yes:
            logger.debug("Envío de transacción cancelado por el usuario")
            return
        
        self.show_loading()
        
        worker = Worker(lambda: self.current_wallet.send_transaction(recipient, amount, token, gas_limit))
        worker.finished.connect(self.on_transaction_sent)
        worker.error.connect(self.on_transaction_error)
        self.active_workers.append(worker)
        logger.debug(f"Iniciando worker para enviar transacción (ID: {id(worker)})")
        worker.start()

    def on_transaction_sent(self, tx_hash):
        logger.debug(f"Transacción enviada exitosamente: {tx_hash}")
        self.show_loading(False)
        QMessageBox.information(self, "Éxito", f"Transacción enviada!\nHash: {tx_hash}")
        self.recipient_address.clear()
        self.send_amount.clear()
        self.update_wallet_info()
        self.cleanup_workers()

    def on_transaction_error(self, error):
        logger.error(f"Error al enviar transacción: {error}")
        self.show_loading(False)
        QMessageBox.critical(self, "Error", f"No se pudo enviar la transacción: {error}")
        self.cleanup_workers()

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