import os
import sys
import json
import pickle
import qrcode
import math
import logging
import time
import requests
import resources_rc
import traceback
import pandas as pd
from datetime import datetime
from cachetools import TTLCache
from cachetools import cachedmethod
from io import BytesIO
from typing import Dict, List, Optional
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from web3 import Web3
from web3.middleware import geth_poa_middleware
from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, 
                            QWidget, QLabel, QLineEdit, QPushButton, QTableWidget,
                            QComboBox, QFileDialog, QMessageBox, QListWidget, 
                            QTabWidget, QFormLayout, QGroupBox, QInputDialog,
                            QTableWidgetItem, QStyle, QHeaderView, QListWidgetItem,
                            QProgressBar, QStackedWidget, QDialog, QDialogButtonBox, 
                            QGraphicsDropShadowEffect, QScrollArea, QFrame, QSlider,
                            QAction)

from PyQt5.QtGui import (QPixmap, QImage, QIcon, QPainter, QBrush, QPen, QColor,
                        QFont, QPainterPath, QDoubleValidator, QIntValidator, 
                        QRadialGradient, QConicalGradient, QDesktopServices)
from PyQt5.QtCore import (Qt, QTimer, QSize, QFile, QIODevice, pyqtSignal, QThread, 
                         QRectF, QPropertyAnimation, QEasingCurve, QPoint, QDateTime,
                         QUrl, QObject, QMetaObject)
from PyQt5.QtChart import QChart, QChartView, QLineSeries, QDateTimeAxis, QValueAxis

# Configuración inicial de logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='solidwallet.log',
    filemode='w'
)
logger = logging.getLogger(__name__)

ETHERSCAN_V2_URL = "https://api.etherscan.io/v2/api"

# Configuración de tokens
TOKEN_CONTRACTS = {
    'BNB': None,
    'USDT': Web3.to_checksum_address('0x55d398326f99059fF775485246999027B3197955'),
    'USDC': Web3.to_checksum_address('0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d')
}

TOKEN_DECIMALS = {
    'BNB': 18,
    'USDT': 18,
    'USDC': 18
}

# Tiempo de sesión en minutos
SESSION_TIMEOUT = 10

BALANCE_CACHE = TTLCache(maxsize=32, ttl=60)  # 60 segundos = 1 minuto
TX_CACHE = TTLCache(maxsize=16, ttl=60)      # 3 minutos

class ConfigManager:
    def __init__(self):
        self.config_file = 'solidwallet_config.json'
        self.config = self._load_config()
        
    def _load_config(self):
        """Carga la configuración desde el archivo"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            except Exception:
                return {'bscscan_api_key': ''}
        return {'bscscan_api_key': ''}
    
    def save_config(self):
        """Guarda la configuración en el archivo"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f)
            return True
        except Exception as e:
            logger.error(f"Error guardando configuración: {str(e)}")
            return False
    
    def get_api_key(self):
        """Obtiene la API key de BscScan/Etherscan"""
        return self.config.get('bscscan_api_key', '')
    
    def set_api_key(self, api_key):
        """Establece la API key de BscScan/Etherscan"""
        self.config['bscscan_api_key'] = api_key.strip()
        return self.save_config()

class Worker(QThread):
    finished = pyqtSignal(object)
    error = pyqtSignal(str)

    def __init__(self, func, *args, **kwargs):
        super().__init__()
        self.func = func
        self.args = args
        self.kwargs = kwargs
        self._is_running = True
        
        # Mover el objeto al hilo principal si es necesario
        self.moveToThread(QApplication.instance().thread())
        
        logger.debug(f"Worker creado para función: {func.__name__}")

    def run(self):
        try:
            logger.debug(f"Iniciando ejecución del worker para función: {self.func.__name__}")
            
            # Mover al hilo principal si es necesario
            if hasattr(self.func, '__self__') and isinstance(self.func.__self__, QObject):
                self.func.__self__.moveToThread(QApplication.instance().thread())
                
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

class BscScanAPI:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://api.etherscan.io/v2/api"  # Usamos Etherscan con chainid=56
        self.last_api_call = 0
        self.api_call_delay = 0.2  # 200ms entre llamadas

    def _rate_limit(self):
        """Controla el rate limiting para la API"""
        elapsed = time.time() - self.last_api_call
        if elapsed < self.api_call_delay:
            time.sleep(self.api_call_delay - elapsed)
        self.last_api_call = time.time()

    def _make_request(self, params):
        """Realiza una petición a la API con los parámetros dados"""
        self._rate_limit()
        try:
            # Asegurarnos que chainid=56 está incluido para BSC
            params['chainid'] = 56
            params['apikey'] = self.api_key
            
            # Imprimir URL completa (para depuración)
            url_with_params = f"{self.base_url}?{'&'.join([f'{k}={v}' for k, v in params.items()])}"
            print("\n[DEBUG] URL de la petición GET:")
            print(url_with_params)
            
            response = requests.get(self.base_url, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            print("\n[DEBUG] Respuesta de la API:")
            print(json.dumps(data, indent=2))  # Formato legible
            
            if data.get('status') != '1':
                logger.error(f"API returned error: {data.get('message', 'Unknown error')}")
                return None
                
            return data.get('result', [])
        except Exception as e:
            logger.error(f"Error making API request: {str(e)}")
            return None


    def get_normal_transactions(self, address, page=1, offset=1000):
        """Obtiene transacciones normales de BNB usando la URL exacta que proporcionaste"""
        params = {
            "module": "account",
            "action": "txlist",
            "address": address,
            "page": page,
            "offset": offset,
            "sort": "asc"
        }
        return self._make_request(params)
    
    def get_token_transactions(self, address, page=1, offset=1000):
        """Obtiene transacciones de tokens (USDT, USDC) usando la URL exacta que proporcionaste"""
        params = {
            "module": "account",
            "action": "tokentx",
            "address": address,
            "page": page,
            "offset": offset,
            "sort": "asc"
        }
        return self._make_request(params)

    def get_balance(self, address):
        """Obtiene el balance de BNB"""
        params = {
            "chainid": 56,
            "module": "account",
            "action": "balance",
            "address": address,
            "tag": "latest",
            "apikey": self.api_key
        }
        return self._make_request(params)

    def get_all_transactions(self, address, tx_type='all', max_pages=10):
        """
        Obtiene todas las transacciones paginadas
        
        Args:
            address (str): Dirección del wallet
            tx_type (str): 'all', 'native' o 'token'
            max_pages (int): Máximo número de páginas a obtener
            
        Returns:
            list: Lista de todas las transacciones
        """
        all_txs = []
        page = 1
        
        while True:
            try:
                txs = []
                token_txs = []
                
                if tx_type in ['all', 'native']:
                    txs = self.get_normal_transactions(address, page=page) or []
                    
                if tx_type in ['all', 'token']:
                    token_txs = self.get_token_transactions(address, page=page) or []
                
                # Agregar transacciones encontradas
                if txs:
                    all_txs.extend(txs)
                if token_txs:
                    all_txs.extend(token_txs)
                
                # Condición de salida: si no hay más transacciones o alcanzamos el máximo de páginas
                if (not txs and not token_txs) or page >= max_pages:
                    break
                    
                page += 1
                    
            except Exception as e:
                logger.error(f"Error getting transactions page {page}: {str(e)}")
                break
                    
        return all_txs

class TransactionFetcher:
    def __init__(self, api_key, chain_id=56):
        self.api_key = api_key
        self.chain_id = chain_id
        self.base_url = "https://api.etherscan.io/v2/api"
        self.last_api_call = 0
        self.api_call_delay = 0.2  # 200ms entre llamadas

    def _rate_limit(self):
        """Controla el rate limiting para la API"""
        elapsed = time.time() - self.last_api_call
        if elapsed < self.api_call_delay:
            time.sleep(self.api_call_delay - elapsed)
        self.last_api_call = time.time()

    def get_all_pages(self, address, action, offset=1000):
        """Obtiene todos los resultados paginados de la API"""
        all_results = []
        page = 1
        
        while True:
            try:
                self._rate_limit()
                logger.debug(f"Obteniendo página {page} para acción {action}")
                
                params = {
                    "chainid": self.chain_id,
                    "module": "account",
                    "action": action,
                    "address": address,
                    "page": page,
                    "offset": offset,
                    "sort": "asc",
                    "apikey": self.api_key
                }
                
                # Imprimir URL antes de la petición
                url_with_params = f"{self.base_url}?{'&'.join([f'{k}={v}' for k, v in params.items()])}"
                print(f"\n[DEBUG] Página {page} - URL GET:")
                print(url_with_params)
                
                response = requests.get(self.base_url, params=params, timeout=10)
                response.raise_for_status()
                
                result = response.json().get("result", [])
                print(f"\n[DEBUG] Respuesta (Página {page}):")
                print(json.dumps(response.json(), indent=2))
                
                if not result:
                    break
                    
                all_results.extend(result)
                
                if len(result) < offset:
                    break  # Última página alcanzada
                    
                page += 1
                
            except Exception as e:
                logger.error(f"Error obteniendo datos para acción {action}: {e}")
                break
                
        return all_results

    def get_normal_transactions(self, address):
        """Obtiene todas las transacciones normales"""
        logger.debug(f"Obteniendo TODAS las transacciones normales para {address}")
        return self.get_all_pages(address, "txlist")

    def get_erc20_transfers(self, address):
        """Obtiene todas las transferencias ERC20"""
        logger.debug(f"Obteniendo TODAS las transferencias ERC20 para {address}")
        return self.get_all_pages(address, "tokentx")

    def get_internal_transactions(self, address):
        """Obtiene todas las transacciones internas"""
        logger.debug(f"Obteniendo TODAS las transacciones internas para {address}")
        return self.get_all_pages(address, "txlistinternal")

    def get_balance(self, address):
        """Obtiene el balance de la cuenta"""
        try:
            self._rate_limit()
            logger.debug(f"Obteniendo balance para {address}")
            
            params = {
                "chainid": self.chain_id,
                "module": "account",
                "action": "balance",
                "address": address,
                "tag": "latest",
                "apikey": self.api_key
            }
            
            response = requests.get(self.base_url, params=params, timeout=10)
            response.raise_for_status()
            
            return response.json().get("result")
            
        except Exception as e:
            logger.error(f"Error obteniendo balance: {e}")
            return None

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
    def __init__(self, private_key=None, web3_provider=None, config_manager=None):
        """
        Inicialización optimizada para BSC
        
        Args:
            private_key (str, optional): Clave privada para wallet existente
            web3_provider (str, optional): URL del proveedor Web3
            config_manager (ConfigManager): Gestor de configuración con API Key
        """
        # Configuración de conexión a Binance Smart Chain
        self.web3 = Web3(Web3.HTTPProvider(
            web3_provider or 'https://bsc-dataseed.binance.org/'
        ))
        self.web3.middleware_onion.inject(geth_poa_middleware, layer=0)
        
        # Configuración de API
        self.config_manager = config_manager
        self.bsc_scan = BscScanAPI(config_manager.get_api_key()) if config_manager else None
        
        # Configuración de tokens BSC (BEP-20)
        self.TOKEN_CONTRACTS = {
            'BNB': None,  # Moneda nativa
            'USDT': Web3.to_checksum_address('0x55d398326f99059fF775485246999027B3197955'),
            'USDC': Web3.to_checksum_address('0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d')
        }
        
        self.TOKEN_DECIMALS = {
            'BNB': 18,
            'USDT': 18,
            'USDC': 18
        }
        
        # Inicialización de cuenta
        if private_key:
            self.account = self.web3.eth.account.from_key(private_key)
        else:
            self.account = self.web3.eth.account.create()
        
        self.address = self.account.address
        self.private_key = self.account.key.hex()

        # Cache inicial
        self._clear_caches()


    def _clear_caches(self):
        """Limpia las cachés existentes"""
        BALANCE_CACHE.clear()
        TX_CACHE.clear()

    @cachedmethod(lambda self: BALANCE_CACHE)
    def get_balance(self, token_symbol='BNB'):
        try:
            if token_symbol not in self.TOKEN_CONTRACTS:
                raise ValueError(f"Token no soportado: {token_symbol}")
                
            if token_symbol == 'BNB':
                if self.bsc_scan:
                    print("\n[DEBUG] Obteniendo balance de BNB via API")
                    balance = self.bsc_scan.get_balance(self.address)
                    if balance is not None:
                        return float(self.web3.from_wei(int(balance), 'ether'))
                
                # Fallback a consulta directa a la blockchain
                print("\n[DEBUG] Obteniendo balance de BNB via Web3")
                balance = self.web3.eth.get_balance(self.address)
                return float(self.web3.from_wei(balance, 'ether'))
            
            print(f"\n[DEBUG] Obteniendo balance de {token_symbol} via contrato")
            contract = self.web3.eth.contract(
                address=self.TOKEN_CONTRACTS[token_symbol],
                abi=self._get_erc20_abi()
            )
            balance = contract.functions.balanceOf(self.address).call()
            return balance / (10 ** self.TOKEN_DECIMALS[token_symbol])
            
        except Exception as e:
            logger.error(f"Error obteniendo balance de {token_symbol}: {str(e)}")
            return None




    @cachedmethod(lambda self: TX_CACHE)
    def get_transactions(self, limit=50):
        """
        Obtiene transacciones combinadas (BNB y tokens) con caché
        
        Args:
            limit (int): Número máximo de transacciones a devolver
            
        Returns:
            list: Lista de transacciones ordenadas por timestamp descendente
        """
        try:
            # Obtener transacciones de la API si está configurada
            if self.bsc_scan:
                native_txs = self._get_transactions_from_api('native')
                token_txs = self._get_transactions_from_api('token')
            else:
                # Fallback a consulta directa si no hay API (limitado)
                native_txs = self._get_recent_transactions_from_blockchain()
                token_txs = []
            
            # Combinar y ordenar
            all_txs = sorted(
                native_txs + token_txs,
                key=lambda x: x['timestamp'],
                reverse=True
            )
            
            return all_txs[:limit]
            
        except Exception as e:
            logger.error(f"Error obteniendo transacciones: {str(e)}")
            return []

    def _get_recent_transactions_from_blockchain(self):
        """Obtiene transacciones recientes directamente de la blockchain (sin API)"""
        try:
            # Solo obtiene las últimas 100 transacciones como máximo
            latest_block = self.web3.eth.block_number
            txs = []
            
            for i in range(latest_block, max(0, latest_block - 100), -1):
                block = self.web3.eth.get_block(i, full_transactions=True)
                for tx in block.transactions:
                    if tx['from'].lower() == self.address.lower() or tx['to'].lower() == self.address.lower():
                        txs.append({
                            'hash': tx['hash'].hex(),
                            'from': tx['from'],
                            'to': tx['to'],
                            'value': float(self.web3.from_wei(tx['value'], 'ether')),
                            'timestamp': block['timestamp'],
                            'gasPrice': float(self.web3.from_wei(tx['gasPrice'], 'gwei')),
                            'gasUsed': 0,  # No disponible sin receipt
                            'isError': '0'  # Asumimos éxito sin API
                        })
                        
            return self._parse_transactions(txs, 'native')
            
        except Exception as e:
            logger.error(f"Error obteniendo transacciones de blockchain: {str(e)}")
            return []

    def sync_all_transactions(self, start_block=0):
        """Sincroniza todas las transacciones desde un bloque inicial"""
        logger.debug(f"Sincronizando transacciones desde el bloque {start_block}")
        
        if not self.bsc_scan:
            logger.error("No hay API key configurada para BscScan")
            return pd.DataFrame()

        try:
            logger.debug("Obteniendo transacciones nativas (BNB)")
            native_txs = self.bsc_scan.get_all_transactions(self.address, tx_type='native')
            logger.debug(f"Encontradas {len(native_txs)} transacciones nativas")
            
            logger.debug("Obteniendo transacciones de tokens")
            token_txs = self.bsc_scan.get_all_transactions(self.address, tx_type='token')
            logger.debug(f"Encontradas {len(token_txs)} transacciones de tokens")
            
            # Parsear transacciones
            parsed_native = self._parse_transactions(native_txs, 'native')
            parsed_token = self._parse_transactions(token_txs, 'token')
            
            # Combinar y ordenar transacciones
            all_txs = parsed_native + parsed_token
            logger.debug(f"Total de transacciones encontradas: {len(all_txs)}")
            
            if not all_txs:
                return pd.DataFrame()
                
            all_txs_sorted = sorted(all_txs, key=lambda x: x['timestamp'], reverse=True)
            
            # Convertir a DataFrame
            df = pd.DataFrame(all_txs_sorted)
            
            # Convertir timestamp a datetime
            if not df.empty and 'timestamp' in df.columns:
                df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')
            
            # Guardar archivo local
            try:
                parquet_file = f"txs_{self.address[:6]}.parquet"
                df.to_parquet(parquet_file)
                logger.debug(f"Transacciones guardadas en {parquet_file}")
            except Exception as e:
                logger.error(f"Error guardando transacciones: {str(e)}")
            
            return df
            
        except Exception as e:
            logger.error(f"Error sincronizando transacciones: {str(e)}")
            return pd.DataFrame()

    def _get_transactions_from_api(self, tx_type):
        """
        Obtiene transacciones de la API
        
        Args:
            tx_type (str): 'native' para BNB o 'token' para USDT/USDC
            
        Returns:
            list: Lista de transacciones parseadas
        """
        try:
            if tx_type == 'native':
                raw_txs = self.bsc_scan.get_all_transactions(self.address, tx_type='native')
            else:
                raw_txs = self.bsc_scan.get_all_transactions(self.address, tx_type='token')
                
            return self._parse_transactions(raw_txs, tx_type)
            
        except Exception as e:
            logger.error(f"Error obteniendo transacciones {tx_type}: {str(e)}")
            return []
        
   
    def _parse_transactions(self, tx_list, tx_type):
        """Parseo de transacciones en formato API"""
        transactions = []
        address_lower = self.address.lower()

        for tx in tx_list:
            try:
                # Convertir timestamp a formato consistente
                if 'timeStamp' in tx:
                    timestamp = int(tx['timeStamp'])
                elif 'timestamp' in tx:
                    timestamp = int(tx['timestamp'])
                else:
                    timestamp = 0

                if tx_type == 'native':
                    # Procesar transacciones nativas (BNB)
                    value = float(tx.get('value', 0)) / 1e18  # Convertir de wei a BNB
                    if value <= 0.000000:  # Filtrar transacciones con valor 0
                        continue
                        
                    tx_data = {
                        'hash': tx.get('hash', ''),
                        'from': tx.get('from', ''),
                        'to': tx.get('to', ''),
                        'value': value,
                        'token': 'BNB',
                        'timestamp': timestamp,
                        'status': 'confirmed' if tx.get('isError', '0') == '0' else 'failed',
                        'blockNumber': int(tx.get('blockNumber', 0)),
                        'fee': (float(tx.get('gasPrice', 0)) * float(tx.get('gasUsed', 21000))) / 1e18,
                        'direction': 'in' if tx.get('to', '').lower() == address_lower else 'out'
                    }
                    transactions.append(tx_data)

                elif tx_type == 'token':
                    # Procesar transacciones de tokens (USDT, USDC)
                    contract_address = tx.get('contractAddress', '').lower()
                    
                    # Identificar el token
                    token_symbol = None
                    for symbol, addr in self.TOKEN_CONTRACTS.items():
                        if addr and addr.lower() == contract_address:
                            token_symbol = symbol
                            break
                    
                    if not token_symbol:
                        token_symbol_from_api = tx.get('tokenSymbol', '').upper()
                        if token_symbol_from_api in ['USDT', 'USDC', 'BSC-USD']:
                            token_symbol = 'USDT' if token_symbol_from_api in ['USDT', 'BSC-USD'] else token_symbol_from_api
                    
                    if not token_symbol:
                        continue
                    
                    # Manejar el valor de la transacción
                    raw_value = tx.get('value', '0')
                    if isinstance(raw_value, str) and raw_value.startswith('0x'):
                        value = int(raw_value, 16)
                    else:
                        value = int(float(raw_value))
                    
                    decimals = self.TOKEN_DECIMALS.get(token_symbol, 18)
                    value_normalized = value / (10 ** decimals)
                    
                    # Filtrar transacciones con valor <= 0.000000
                    if value_normalized <= 0.000000:
                        continue
                    
                    # Validar que la transacción involucre nuestra dirección
                    if tx.get('to', '').lower() != address_lower and tx.get('from', '').lower() != address_lower:
                        continue
                    
                    tx_data = {
                        'hash': tx.get('hash', ''),
                        'from': tx.get('from', ''),
                        'to': tx.get('to', ''),
                        'value': value_normalized,
                        'token': token_symbol,
                        'timestamp': timestamp,
                        'status': 'confirmed',
                        'blockNumber': int(tx.get('blockNumber', 0)),
                        'fee': (float(tx.get('gasPrice', 0)) * float(tx.get('gasUsed', 0))) / 1e18,
                        'direction': 'in' if tx.get('to', '').lower() == address_lower else 'out'
                    }
                    transactions.append(tx_data)

            except Exception as e:
                logger.error(f"Error parseando transacción ({tx_type}): {str(e)}\nTransacción: {json.dumps(tx, indent=2)}")
                continue

        return transactions
    
    def send_transaction(self, recipient, amount, token_symbol='BNB', gas_price=None, gas_limit=None):
        """Envía una transacción con gas optimizado"""
        logger.debug(f"Enviando transacción de {amount} {token_symbol} a {recipient}")
        
        try:
            recipient = Web3.to_checksum_address(recipient)
            
            if gas_price is None or gas_limit is None:
                gas_params = self.calculate_optimal_gas(token_symbol)
                gas_price = gas_params['gas_price']
                gas_limit = gas_params['gas_limit']
            
            gas_price_wei = self.web3.to_wei(gas_price, 'gwei')
            
            if token_symbol == 'BNB':
                tx = {
                    'to': recipient,
                    'value': self.web3.to_wei(amount, 'ether'),
                    'gas': gas_limit,
                    'gasPrice': gas_price_wei,
                    'nonce': self.web3.eth.get_transaction_count(self.address),
                    'chainId': 56  # BSC chain ID
                }
                
                signed_tx = self.web3.eth.account.sign_transaction(tx, self.private_key)
                tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
            else:
                contract = self.web3.eth.contract(
                    address=TOKEN_CONTRACTS[token_symbol],
                    abi=self._get_erc20_abi()
                )
                
                amount_wei = int(amount * (10 ** TOKEN_DECIMALS[token_symbol]))
                
                tx = contract.functions.transfer(
                    recipient,
                    amount_wei
                ).build_transaction({
                    'gas': gas_limit,
                    'gasPrice': gas_price_wei,
                    'nonce': self.web3.eth.get_transaction_count(self.address),
                    'chainId': 56
                })
                
                signed_tx = self.web3.eth.account.sign_transaction(tx, self.private_key)
                tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
            
            logger.debug(f"Transacción enviada con hash: {tx_hash.hex()}")
            return tx_hash.hex()
            
        except Exception as e:
            logger.error(f"Error enviando transacción: {str(e)}")
            raise

    def calculate_optimal_gas(self, token_symbol='BNB', speed='medium'):
        """Calcula valores óptimos de gas basados en condiciones de red"""
        try:
            current_gas = float(self.web3.from_wei(
                self.web3.eth.gas_price, 
                'gwei'
            ))
            
            speed_multipliers = {
                'low': 0.7,     # Económico
                'medium': 1.0,   # Estándar
                'high': 1.3,     # Rápido
                'urgent': 2.0    # Urgente
            }
            
            if speed not in speed_multipliers:
                speed = 'medium'
            
            gas_price = round(current_gas * speed_multipliers[speed], 1)
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
        """
        Devuelve el ABI mínimo para interactuar con tokens BEP-20
        
        Returns:
            list: ABI en formato JSON
        """
        return [
            {
                "constant": True,
                "inputs": [{"name": "_owner", "type": "address"}],
                "name": "balanceOf",
                "outputs": [{"name": "balance", "type": "uint256"}],
                "type": "function"
            },
            {
                "constant": False,
                "inputs": [
                    {"name": "_to", "type": "address"},
                    {"name": "_value", "type": "uint256"}
                ],
                "name": "transfer",
                "outputs": [{"name": "", "type": "bool"}],
                "type": "function"
            },
            {
                "constant": True,
                "inputs": [],
                "name": "decimals",
                "outputs": [{"name": "", "type": "uint8"}],
                "type": "function"
            }
        ]

    def generate_qr_code(self, data, size=250):
        """Genera un QR code como QPixmap"""
        try:
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_H,
                box_size=10,
                border=4,
            )
            qr.add_data(data)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="#4e9af1", back_color="#ffffff")
            img = img.convert("RGBA")
            
            # Convertir a QPixmap
            data = img.tobytes("raw", "RGBA")
            qimg = QImage(data, img.size[0], img.size[1], QImage.Format_RGBA8888)
            pixmap = QPixmap.fromImage(qimg)
            
            # Aplicar efectos visuales
            final_pixmap = QPixmap(pixmap.size())
            final_pixmap.fill(Qt.transparent)
            
            painter = QPainter(final_pixmap)
            painter.setRenderHint(QPainter.Antialiasing)
            
            # Sombra
            shadow = QPainterPath()
            shadow.addRoundedRect(QRectF(5, 5, pixmap.width(), pixmap.height()), 10, 10)
            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor(0, 0, 0, 50))
            painter.drawPath(shadow)
            
            # Fondo blanco redondeado
            bg_path = QPainterPath()
            bg_path.addRoundedRect(QRectF(0, 0, pixmap.width(), pixmap.height()), 10, 10)
            painter.setPen(Qt.NoPen)
            painter.setBrush(Qt.white)
            painter.drawPath(bg_path)
            
            # Dibujar QR code
            painter.drawPixmap(0, 0, pixmap)
            painter.end()
            
            return final_pixmap.scaled(size, size, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            
        except Exception as e:
            logger.error(f"Error generando QR code: {str(e)}")
            raise

class WalletManager:
    def __init__(self, config_manager=None):
        logger.debug("Inicializando WalletManager")
        self.wallets = {}
        self.config_manager = config_manager
        self.wallet_files = []
        self._load_wallet_files()  # Cargar al inicializar
        logger.debug(f"WalletManager inicializado con {len(self.wallet_files)} wallets cargados")
    

    def _load_wallet_files(self):
        """Carga la lista de wallets desde el archivo de configuración"""
        try:
            if os.path.exists('wallets.json'):
                with open('wallets.json', 'r') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        self.wallet_files = [f for f in data if isinstance(f, str) and os.path.exists(f)]
                        logger.debug(f"Wallets cargados: {self.wallet_files}")
                        return
            # Si falla, crear archivo nuevo
            self.wallet_files = []
            self._save_wallet_files()
        except Exception as e:
            logger.error(f"Error cargando wallets.json: {str(e)}")
            self.wallet_files = []
            self._save_wallet_files()

    def save_config(self):
        """Guarda la lista de wallets en el archivo"""
        try:
            with open('wallets.json', 'w') as f:
                json.dump(self.wallet_files, f)
            logger.debug("Lista de wallets guardada correctamente")
        except Exception as e:
            logger.error(f"Error guardando wallets.json: {str(e)}")
            raise

    def _save_wallet_files(self):
        """Guarda la lista de wallets en el archivo de configuración"""
        try:
            with open('wallets.json', 'w') as f:
                json.dump(self.wallet_files, f)
            logger.debug(f"Wallets guardados: {self.wallet_files}")
        except Exception as e:
            logger.error(f"Error guardando wallets.json: {str(e)}")
            raise

    def add_wallet_file(self, file_path):
        """Agrega un archivo de wallet a la lista"""
        abs_path = os.path.abspath(file_path)
        if abs_path not in self.wallet_files:
            self.wallet_files.append(abs_path)
            self.save_config()
            return True
        return False

    
    def create_wallet(self):
        """Crea una nueva wallet"""
        logger.debug("Creando nuevo wallet")
        return CryptoWallet(config_manager=self.config_manager)
    
    def encrypt_wallet(self, wallet, password, file_path):
        """Cifra y guarda una wallet en un archivo"""
        logger.debug(f"Cifrando wallet para guardar en {file_path}")
        try:
            wallet_data = {
                'address': wallet.address,
                'private_key': wallet.private_key,
                'web3_provider': wallet.web3.provider.endpoint_uri
            }
            
            salt = get_random_bytes(16)
            key = scrypt(password, salt, key_len=32, N=2**14, r=8, p=1)
            serialized = pickle.dumps(wallet_data)
            
            # PKCS7 padding
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
            
            # Asegurar que la ruta sea absoluta y añadir a la lista
            abs_path = os.path.abspath(file_path)
            if abs_path not in self.wallet_files:
                self.wallet_files.append(abs_path)
                self._save_wallet_files()  # Guardar inmediatamente
            return abs_path
        except Exception as e:
            logger.error(f"Error cifrando wallet: {str(e)}")
            raise
    
    def decrypt_wallet(self, file_path, password):
        """Descifra una wallet desde archivo"""
        try:
            with open(file_path, 'r') as f:
                encrypted_data = json.load(f)
                
            # Proceso de descifrado
            salt = bytes.fromhex(encrypted_data['salt'])
            nonce = bytes.fromhex(encrypted_data['nonce'])
            tag = bytes.fromhex(encrypted_data['tag'])
            ciphertext = bytes.fromhex(encrypted_data['ciphertext'])
            
            key = scrypt(password, salt, key_len=32, N=2**14, r=8, p=1)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)
            
            # Quitar padding PKCS7
            padding_length = decrypted[-1]
            decrypted = decrypted[:-padding_length]
            
            wallet_data = pickle.loads(decrypted)
            return CryptoWallet(
                private_key=wallet_data['private_key'],
                web3_provider=wallet_data['web3_provider'],
                config_manager=self.config_manager
            )
        except Exception as e:
            logger.error(f"Error descifrando wallet: {str(e)}")
            raise ValueError("Contraseña incorrecta o archivo inválido")
        
    
class ConfigDialog(QDialog):
    def __init__(self, config_manager, parent=None):
        super().__init__(parent)
        self.config_manager = config_manager
        self.setWindowTitle("Configuración")
        self.setWindowIcon(QIcon(":/icons/settings.svg"))
        self.setMinimumWidth(400)
        
        layout = QVBoxLayout()
        
        form = QFormLayout()
        
        self.api_key_edit = QLineEdit()
        self.api_key_edit.setPlaceholderText("Ingrese su API Key de BscScan/Etherscan")
        self.api_key_edit.setText(self.config_manager.get_api_key())
        
        form.addRow("API Key BscScan/Etherscan:", self.api_key_edit)
        
        help_label = QLabel(
            '<a href="https://bscscan.com/apidashboard">Obtener API Key de BscScan</a> | '
            '<a href="https://etherscan.io/apidashboard">Obtener API Key de Etherscan</a>'
        )
        help_label.setOpenExternalLinks(True)
        
        layout.addLayout(form)
        layout.addWidget(help_label)
        
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        
        self.setLayout(layout)
    
    def accept(self):
        api_key = self.api_key_edit.text().strip()
        if not api_key:
            QMessageBox.warning(self, "Advertencia", "Por favor ingrese una API Key válida")
            return
            
        if not self.config_manager.set_api_key(api_key):
            QMessageBox.critical(self, "Error", "No se pudo guardar la configuración")
            return
            
        super().accept()

class NoConnectionWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignCenter)
        layout.setContentsMargins(30, 30, 30, 30)
        
        icon = QLabel()
        icon.setPixmap(QPixmap(":/icons/warning.svg").scaled(64, 64, Qt.KeepAspectRatio))
        icon.setAlignment(Qt.AlignCenter)
        
        title = QLabel("Conexión con BscScan no configurada")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #f39c12;")
        title.setAlignment(Qt.AlignCenter)
        
        message = QLabel(
            "Para acceder al historial completo de transacciones, necesitas configurar una API Key de BscScan.\n\n"
            "Sin una API Key válida, solo podrás ver transacciones recientes directamente desde la blockchain."
        )
        message.setWordWrap(True)
        message.setAlignment(Qt.AlignCenter)
        
        btn_config = QPushButton("Configurar API Key")
        btn_config.setStyleSheet("background-color: #4e9af1; color: white; padding: 10px;")
        btn_config.clicked.connect(self.open_config)
        
        btn_get_key = QPushButton("Obtener API Key")
        btn_get_key.setStyleSheet("background-color: #2ecc71; color: white; padding: 10px;")
        btn_get_key.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://bscscan.com/apidashboard")))
        
        btn_container = QWidget()
        btn_layout = QHBoxLayout(btn_container)
        btn_layout.addWidget(btn_config)
        btn_layout.addWidget(btn_get_key)
        
        layout.addWidget(icon)
        layout.addWidget(title)
        layout.addWidget(message)
        layout.addWidget(btn_container)
        
        self.setLayout(layout)
    
    def open_config(self):
        parent = self.parent()
        while parent and not isinstance(parent, QMainWindow):
            parent = parent.parent()
        if parent:
            parent.show_config_dialog()



class SolidWalletGUI(QMainWindow):
    update_chart_signal = pyqtSignal(str, object)

    def __init__(self):
        super().__init__()
        logger.debug("Inicializando SolidWalletGUI")
        
        # Configuración inicial
        self.config_manager = ConfigManager()
        self.wallet_manager = WalletManager(self.config_manager)
        self.current_wallet = None
        self.current_file = None
        self.last_activity = datetime.now()
        self.online = True
        self.active_workers = []
        self.bnb_price = 280  # Valor por defecto
        self.current_gas_prices = {'low': 3, 'medium': 5, 'high': 10, 'urgent': 20}
        
        # Configurar UI
        self.setup_window()
        self.setup_ui()
        self.setup_timers()
        
        self.update_chart_signal.connect(self._handle_chart_update)

        self.load_wallet_list()
        # Mostrar vista inicial
        if self.wallet_manager.wallet_files:
            self.stacked_widget.setCurrentIndex(0)
            self.show_empty_state()
        else:
            self.stacked_widget.setCurrentIndex(2)
        
        logger.debug("SolidWalletGUI inicializado correctamente")




   

    def setup_window(self):
        """Configuración básica de la ventana"""
        self.setWindowTitle("SolidWallet - BSC Wallet")
        self.resize(1200, 800)
        self.setMinimumSize(1000, 700)
        self.setWindowIcon(QIcon(":/icons/solidwallet.png"))
        self.setStyleSheet(self.get_stylesheet())
        self.center_on_screen()

    def setup_ui(self):
        """Configura todos los componentes de la UI"""
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
        
        # Widget de loading
        self.loading_widget = LoadingWidget()
        loading_container = QWidget()
        loading_layout = QVBoxLayout()
        loading_layout.addWidget(self.loading_widget, 0, Qt.AlignCenter)
        loading_container.setLayout(loading_layout)
        
        # Stack principal
        self.stacked_widget = QStackedWidget()
        self.stacked_widget.addWidget(self.central_widget)
        self.stacked_widget.addWidget(loading_container)
        self.stacked_widget.addWidget(self.no_wallet_widget)
        self.setCentralWidget(self.stacked_widget)
        
        # Barra de estado
        self.setup_status_bar()
        # Barra de menú
        self.setup_menu_bar()

    def on_send_button_clicked(self):
        """Maneja el clic en el botón de enviar"""
        try:
            # Obtener valores de los campos
            token_symbol = self.token_combo.currentText()
            recipient = self.recipient_address.text().strip()
            amount_text = self.send_amount.text().strip()
            
            # Validaciones básicas
            if not recipient:
                QMessageBox.warning(self, "Error", "Ingrese una dirección destino")
                return
                
            if not amount_text:
                QMessageBox.warning(self, "Error", "Ingrese una cantidad")
                return
                
            try:
                amount = float(amount_text)
            except ValueError:
                QMessageBox.warning(self, "Error", "Cantidad inválida")
                return
                
            if amount <= 0:
                QMessageBox.warning(self, "Error", "La cantidad debe ser mayor que 0")
                return
                
            # Obtener parámetros de gas
            if self.advanced_group.isChecked():
                # Usar valores manuales
                try:
                    gas_price = float(self.gas_price_input.text())
                    gas_limit = int(self.gas_limit_input.text())
                except ValueError:
                    QMessageBox.warning(self, "Error", "Valores de gas inválidos")
                    return
            else:
                # Calcular automáticamente
                gas_params = self.current_wallet.calculate_optimal_gas(token_symbol)
                gas_price = gas_params['gas_price']
                gas_limit = gas_params['gas_limit']
                
            # Mostrar confirmación
            confirm_msg = (
                f"¿Confirmar envío de {amount} {token_symbol} a {recipient}?\n\n"
                f"Tarifa estimada: {(gas_price * gas_limit)/1e9:.6f} BNB (~${(gas_price * gas_limit)/1e9 * self.bnb_price:.2f} USD)"
            )
            
            reply = QMessageBox.question(
                self, 'Confirmar Transacción', 
                confirm_msg,
                QMessageBox.Yes | QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                self.show_loading("Enviando transacción...")
                
                # Usar el método send_transaction de CryptoWallet
                worker = Worker(
                    self.current_wallet.send_transaction,
                    recipient,
                    amount,
                    token_symbol,
                    gas_price,
                    gas_limit
                )
                worker.finished.connect(self.on_transaction_sent)
                worker.error.connect(self.on_transaction_error)
                self.active_workers.append(worker)
                worker.start()
                
        except Exception as e:
            self.show_loading(False)
            QMessageBox.critical(self, "Error", f"Error al preparar transacción: {str(e)}")

    def setup_menu_bar(self):
        """Configura la barra de menú"""
        menubar = self.menuBar()
        
        # Menú Archivo
        file_menu = menubar.addMenu("Archivo")
        
        config_action = QAction("Configuración", self)
        config_action.setShortcut("Ctrl+,")
        config_action.triggered.connect(self.show_config_dialog)
        file_menu.addAction(config_action)
        
        exit_action = QAction("Salir", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Menú Ayuda
        help_menu = menubar.addMenu("Ayuda")
        
        about_action = QAction("Acerca de", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def show_config_dialog(self):
        """Muestra el diálogo de configuración"""
        dialog = ConfigDialog(self.config_manager, self)
        if dialog.exec_() == QDialog.Accepted:
            QMessageBox.information(self, "Éxito", "Configuración guardada correctamente")
            
            # Actualizar la referencia al config_manager en el wallet actual
            if self.current_wallet:
                self.current_wallet.config_manager = self.config_manager
            
            # Actualizar la vista de transacciones
            self.check_api_key_configured()
            if self.current_wallet:
                self.update_wallet_info()

    def show_about(self):
        """Muestra el diálogo Acerca de"""
        QMessageBox.about(self, "Acerca de SolidWallet",
            "SolidWallet - Billetera para Binance Smart Chain\n\n"
            "Versión 1.0\n"
            "Para obtener una API Key de BscScan/Etherscan, visite:\n"
            "https://bscscan.com/apidashboard o https://etherscan.io/apidashboard")

    def check_api_key_configured(self):
        """Verifica si hay una API key configurada y actualiza la vista"""
        if hasattr(self, 'tx_stack'):
            if self.config_manager.get_api_key():
                self.tx_stack.setCurrentIndex(1)  # Mostrar historial
            else:
                self.tx_stack.setCurrentIndex(0)  # Mostrar mensaje de configuración

    def setup_status_bar(self):
        """Configura la barra de estado con conectividad"""
        self.connectivity_icon = QLabel()
        self.connectivity_icon.setFixedSize(32, 32)
        self.connectivity_icon.setScaledContents(True)
        self.update_connectivity_icon()
        
        # Botón de configuración en la barra de estado
        self.config_button = QPushButton()
        self.config_button.setIcon(QIcon(":/icons/settings.svg"))
        self.config_button.setFlat(True)
        self.config_button.setFixedSize(32, 32)
        self.config_button.setToolTip("Configuración")
        self.config_button.clicked.connect(self.show_config_dialog)
        
        self.statusBar().addPermanentWidget(self.connectivity_icon)
        self.statusBar().addPermanentWidget(self.config_button)
        self.statusBar().showMessage("Conectado", 3000)

    def setup_timers(self):
        """Configura los timers para actualizaciones automáticas"""
        # Timer para actualizar gas prices
        self.gas_price_timer = QTimer(self)
        self.gas_price_timer.timeout.connect(self.update_gas_prices)
        self.gas_price_timer.start(5000)  # 5 segundos
        
        # Timer para verificar conectividad
        self.connectivity_timer = QTimer(self)
        self.connectivity_timer.timeout.connect(self.check_connectivity)
        self.connectivity_timer.start(10000)  # 10 segundos
        
        # Timer para verificar sesión
        self.session_timer = QTimer(self)
        self.session_timer.timeout.connect(self.check_session)
        self.session_timer.start(60000)  # 1 minuto

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

    def update_connectivity_icon(self):
        """Actualiza el ícono de conectividad"""
        icon_size = QSize(32, 32)
        
        if self.online:
            icon = QIcon(":/icons/online.png")
            self.connectivity_icon.setPixmap(icon.pixmap(icon_size))
            self.connectivity_icon.setToolTip("Conectado a internet")
        else:
            icon = QIcon(":/icons/offline.png")
            self.connectivity_icon.setPixmap(icon.pixmap(icon_size))
            self.connectivity_icon.setToolTip("Sin conexión a internet")

    def update_ui_for_connectivity(self):
        """Habilita/deshabilita controles según conectividad"""
        enable = self.online
        
        if hasattr(self, 'btn_new'):
            self.btn_new.setEnabled(enable)
            self.btn_load.setEnabled(enable)
            self.btn_delete.setEnabled(enable)
        
        if hasattr(self, 'send_button'):
            self.send_button.setEnabled(enable)

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

    def get_bnb_price(self):
        """Obtiene el precio actual de BNB en USD"""
        if not self.online:
            raise ConnectionError("No hay conexión a internet")
        
        try:
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

            response = requests.post(url, json=payload, headers=headers, timeout=5)
            response.raise_for_status()
            
            data = response.json()
            if data and 'data' in data and len(data['data']) > 0:
                return float(data['data'][0]['d'][0])
            
            raise ValueError("Datos de TradingView no válidos")
                
        except Exception as e:
            logger.error(f"Error obteniendo precio BNB: {str(e)}")
            raise

    def show_empty_state(self):
        """Muestra el estado sin wallet cargado"""
        self.empty_right_panel.setVisible(True)
        self.wallet_right_panel.setVisible(False)
        self.reset_wallet_info()

    def show_wallet_state(self):
        """Muestra el estado con wallet cargado"""
        self.empty_right_panel.setVisible(False)
        self.wallet_right_panel.setVisible(True)

    def reset_wallet_info(self):
        """Resetea la información mostrada del wallet"""
        self.address_label.setText("No hay billetera cargada")
        self.bnb_balance.setText("0.0")
        self.usdt_balance.setText("0.0")
        self.usdc_balance.setText("0.0")
        self.qr_code_label.clear()
        self.qr_code_label.setText("Seleccione una billetera")
        self.qr_code_label.setStyleSheet("color: #666; font-style: italic;")
        self.summary_table.setRowCount(0)
        
    def setup_left_panel(self):
        """Configura el panel izquierdo con la lista de wallets"""
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
        """Elimina la wallet seleccionada de la lista"""
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
                # Limpiar cachés si es la wallet actual
                if file_path == self.current_file:
                    if hasattr(self, 'current_wallet') and self.current_wallet:
                        self.current_wallet._clear_caches()
                    self.logout()
                
                # Eliminar de la lista
                self.wallet_manager.wallet_files.remove(file_path)
                self.wallet_manager._save_wallet_files()
                
                # Actualizar lista visual
                self.load_wallet_list()
                
                # Mostrar estado inicial si no hay wallets
                if not self.wallet_manager.wallet_files:
                    self.stacked_widget.setCurrentIndex(2)
                    self.reset_wallet_info()
                    
            except Exception as e:
                QMessageBox.critical(self, "Error", f"No se pudo eliminar: {str(e)}")

    def setup_empty_right_panel(self):
        """Configura el panel derecho vacío"""
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
        """Configura el panel derecho con la información del wallet"""
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
        
        # Stack para mostrar historial o mensaje de configuración
        self.tx_stack = QStackedWidget()
        
        # Widget de configuración requerida
        self.no_connection_widget = NoConnectionWidget()
        self.tx_stack.addWidget(self.no_connection_widget)
        
        # Widget de historial principal
        self.history_widget = QWidget()
        history_layout = QVBoxLayout()
        
        # Filtro por tipo de moneda
        filter_container = QWidget()
        filter_layout = QHBoxLayout(filter_container)
        
        self.token_filter_combo = QComboBox()
        self.token_filter_combo.addItems(["Todas", "BNB", "USDT", "USDC"])
        self.token_filter_combo.currentTextChanged.connect(self._filter_transactions_by_token)
        
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Buscar por dirección, hash o valor...")
        self.search_edit.textChanged.connect(self._filter_transactions_by_token)
        
        filter_layout.addWidget(QLabel("Filtrar por moneda:"))
        filter_layout.addWidget(self.token_filter_combo)
        filter_layout.addWidget(self.search_edit)
        
        history_layout.addWidget(filter_container)
        
        # Tabla de transacciones (ahora muestra todas mezcladas)
        self.summary_table = QTableWidget()
        self.summary_table.setColumnCount(7)
        self.summary_table.setHorizontalHeaderLabels([
            "Fecha", "Moneda", "Tipo", "Valor", "Contraparte", "Hash", "Estado"
        ])
        self.summary_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.summary_table.setSortingEnabled(True)
        self.summary_table.doubleClicked.connect(self.show_tx_details)
        
        # Label para mostrar mensaje cuando no hay datos
        self.no_tx_label = QLabel("No hay transacciones disponibles")
        self.no_tx_label.setAlignment(Qt.AlignCenter)
        self.no_tx_label.setStyleSheet("font-size: 14px; color: #666;")
        self.no_tx_label.hide()
        
        history_layout.addWidget(self.summary_table)
        history_layout.addWidget(self.no_tx_label)
        self.history_widget.setLayout(history_layout)
        self.tx_stack.addWidget(self.history_widget)
        
        tx_layout.addWidget(self.tx_stack)
        self.tx_tab.setLayout(tx_layout)
        self.tabs.addTab(self.tx_tab, QIcon(":/icons/history.svg"), "Historial")
        
        # Verificar si hay API key configurada
        self.check_api_key_configured()

    def _create_summary_tab(self):
        """Crea la pestaña de resumen con todas las transacciones mezcladas"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Filtro por tipo de moneda
        filter_container = QWidget()
        filter_layout = QHBoxLayout(filter_container)
        
        self.token_filter_combo = QComboBox()
        self.token_filter_combo.addItems(["Todas", "BNB", "USDT", "USDC"])
        self.token_filter_combo.currentTextChanged.connect(self._filter_transactions_by_token)
        
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Buscar por dirección, hash o valor...")
        self.search_edit.textChanged.connect(self._filter_transactions_by_token)
        
        filter_layout.addWidget(QLabel("Filtrar por moneda:"))
        filter_layout.addWidget(self.token_filter_combo)
        filter_layout.addWidget(self.search_edit)
        
        layout.addWidget(filter_container)
        
        # Tabla de transacciones (ahora muestra todas mezcladas)
        self.summary_table = QTableWidget()
        self.summary_table.setColumnCount(7)  # Añadimos columna para el token
        self.summary_table.setHorizontalHeaderLabels([
            "Fecha", "Moneda", "Tipo", "Valor", "Contraparte", "Hash", "Estado"
        ])
        self.summary_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.summary_table.setSortingEnabled(True)
        self.summary_table.doubleClicked.connect(self.show_tx_details)
        
        layout.addWidget(self.summary_table)
        tab.setLayout(layout)
        return tab
    
    
    def _filter_transactions_by_token(self):
        """Filtra la tabla de transacciones por tipo de moneda"""
        selected_token = self.token_filter_combo.currentText()
        search_text = self.search_edit.text().lower()
        
        visible_rows = 0
        
        for row in range(self.summary_table.rowCount()):
            token_item = self.summary_table.item(row, 1)  # Columna de Moneda
            should_show = True
            
            # Filtrar por tipo de moneda
            if selected_token != "Todas":
                should_show = token_item.text() == selected_token
            
            # Filtrar por búsqueda
            if should_show and search_text:
                row_text = " ".join([
                    self.summary_table.item(row, col).text().lower() 
                    for col in range(self.summary_table.columnCount())
                    if self.summary_table.item(row, col) is not None
                ])
                should_show = search_text in row_text
            
            self.summary_table.setRowHidden(row, not should_show)
            if should_show:
                visible_rows += 1
        
        # Mostrar mensaje si no hay transacciones visibles
        if visible_rows == 0:
            if selected_token == "Todas":
                self.no_tx_label.setText("No hay transacciones disponibles")
            else:
                self.no_tx_label.setText(f"No hay transacciones de {selected_token} que coincidan con el filtro")
            self.no_tx_label.show()
            self.summary_table.hide()
        else:
            self.no_tx_label.hide()
            self.summary_table.show()


    def _create_token_tab(self, token):
        """Crea una pestaña para un token específico"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Añadir filtros
        filter_container = QWidget()
        filter_layout = QHBoxLayout(filter_container)
        
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["Todas", "Entradas", "Salidas"])
        self.filter_combo.currentTextChanged.connect(lambda: self._filter_token_table(token))
        
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Buscar por dirección o hash...")
        self.search_edit.textChanged.connect(lambda: self._filter_token_table(token))
        
        filter_layout.addWidget(QLabel("Filtrar:"))
        filter_layout.addWidget(self.filter_combo)
        filter_layout.addWidget(self.search_edit)
        
        layout.addWidget(filter_container)
        
        # Gráfico de histórico
        chart = QChartView()
        chart.setRenderHint(QPainter.Antialiasing)
        layout.addWidget(chart)
        
        # Tabla de transacciones
        table = QTableWidget()
        table.setColumnCount(6)
        table.setHorizontalHeaderLabels(["Fecha", "Tipo", "Valor", "Contraparte", "Hash", "Estado"])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        # Configurar doble clic para ver detalles
        table.doubleClicked.connect(self.show_tx_details)
        
        layout.addWidget(table)
        tab.setLayout(layout)
        
        # Guardar referencia para actualización
        setattr(self, f"{token.lower()}_tx_table", table)
        setattr(self, f"{token.lower()}_tx_chart", chart)
        setattr(self, f"{token.lower()}_search_edit", self.search_edit)
        setattr(self, f"{token.lower()}_filter_combo", self.filter_combo)
        
        return tab

    def _filter_token_table(self, token):
        """Filtra la tabla de transacciones por token"""
        table = getattr(self, f"{token.lower()}_tx_table")
        search_text = getattr(self, f"{token.lower()}_search_edit").text().lower()
        filter_type = getattr(self, f"{token.lower()}_filter_combo").currentText()
        
        for row in range(table.rowCount()):
            should_show = True
            
            # Filtrar por tipo
            if filter_type == "Entradas":
                should_show = table.item(row, 1).text() == "Entrada"
            elif filter_type == "Salidas":
                should_show = table.item(row, 1).text() == "Salida"
            
            # Filtrar por búsqueda
            if should_show and search_text:
                row_text = " ".join([
                    table.item(row, col).text().lower() 
                    for col in range(table.columnCount())
                ])
                should_show = search_text in row_text
            
            table.setRowHidden(row, not should_show)

    def show_tx_details(self, index):
        row = index.row()
        table = self.sender()
        details = []
        for col in range(table.columnCount()):
            header = table.horizontalHeaderItem(col).text()
            item = table.item(row, col)
            value = item.text() if item else "N/A"
            details.append(f"{header}: {value}")
        QMessageBox.information(self, "Detalles de Transacción", "\n".join(details))

    def setup_send_tab(self):
        """Configura la pestaña para enviar transacciones"""
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
        self.send_button.clicked.connect(self.on_send_button_clicked)
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

    def on_gas_price_changed(self):
        """Cuando el usuario modifica manualmente el gas price"""
        if self.advanced_group.isChecked() and self.gas_price_input.text():
            try:
                gas_price = float(self.gas_price_input.text())
                self.update_estimated_fee()
            except ValueError:
                pass

    def create_no_wallet_widget(self):
        """Crea el widget para cuando no hay wallets cargados"""
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
        """Devuelve la hoja de estilos CSS para la aplicación"""
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
    
    def load_wallet_list(self):
        """Carga la lista de wallets en el panel izquierdo"""
        try:
            self.wallet_list.clear()
            if not self.wallet_manager.wallet_files:
                empty_item = QListWidgetItem("No hay wallets cargadas")
                empty_item.setFlags(Qt.NoItemFlags)  # Hacerlo no seleccionable
                self.wallet_list.addItem(empty_item)
                return
                
            for wallet_file in self.wallet_manager.wallet_files:
                item = QListWidgetItem(os.path.basename(wallet_file))
                item.setData(Qt.UserRole, wallet_file)
                item.setIcon(self.style().standardIcon(QStyle.SP_FileLinkIcon))
                self.wallet_list.addItem(item)
        except Exception as e:
            logger.error(f"Error cargando lista de wallets: {str(e)}")
            error_item = QListWidgetItem("Error cargando wallets")
            error_item.setForeground(QColor('red'))
            error_item.setFlags(Qt.NoItemFlags)
            self.wallet_list.addItem(error_item)
            
    def create_password_dialog(self, title, message):
        """Crea un diálogo para ingresar contraseña"""
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
        """Crea una nueva wallet cifrada"""
        self.update_last_activity()
        logger.debug("Iniciando creación de nuevo wallet")
        
        try:
            # Paso 1: Obtener y validar contraseña
            result, password = self.create_password_dialog(
                "Contraseña", 
                "Ingrese una contraseña segura para cifrar la billetera:"
            )
            
            if not result or not password:
                logger.debug("Creación de wallet cancelada por el usuario")
                return
            
            # Validaciones de contraseña
            if len(password) < 8:
                self.show_password_error("La contraseña debe tener al menos 8 caracteres.")
                return
            
            if not any(c.isupper() for c in password):
                self.show_password_error("La contraseña debe contener al menos una mayúscula.")
                return
            
            if not any(c.isdigit() for c in password):
                self.show_password_error("La contraseña debe contener al menos un número.")
                return
            
            # Confirmar contraseña
            result, confirm_password = self.create_password_dialog(
                "Confirmar Contraseña", 
                "Vuelva a ingresar la contraseña para confirmar:"
            )
            
            if not result or password != confirm_password:
                self.show_password_error("Las contraseñas no coinciden.")
                return
            
            # Paso 2: Crear wallet en memoria
            wallet = self.wallet_manager.create_wallet()
            logger.debug(f"Wallet creado en memoria: {wallet.address}")
            
            # Paso 3: Seleccionar ubicación para guardar
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
            
            # Paso 4: Mostrar estado de carga
            self.show_loading()
            
            # Paso 5: Crear y configurar worker para el cifrado
            worker = Worker(self._encrypt_and_save_wallet, wallet, password, file_path)
            worker.finished.connect(lambda success: self.on_wallet_created(success, wallet, file_path))
            worker.error.connect(self.on_wallet_create_error)
            self.active_workers.append(worker)
            
            logger.debug(f"Iniciando worker para cifrar wallet (ID: {id(worker)})")
            worker.start()
            
        except Exception as e:
            logger.error(f"Error en create_new_wallet: {str(e)}")
            self.show_loading(False)
            QMessageBox.critical(self, "Error", f"No se pudo crear la billetera: {str(e)}")

    def _encrypt_and_save_wallet(self, wallet, password, file_path):
        """Método auxiliar para el worker que maneja el cifrado y guardado"""
        try:
            logger.debug(f"Cifrando wallet para {file_path}")
            saved_path = self.wallet_manager.encrypt_wallet(wallet, password, file_path)
            logger.debug(f"Wallet cifrado guardado en: {saved_path}")
            return True
        except Exception as e:
            logger.error(f"Error en _encrypt_and_save_wallet: {str(e)}")
            raise

    def on_wallet_created(self, success, wallet, file_path):
        """Maneja la finalización exitosa del worker de creación"""
        try:
            logger.debug(f"Wallet creado con éxito: {success}")
            if not success:
                raise Exception("No se pudo crear el wallet")
                
            # Actualizar estado actual
            self.current_wallet = wallet
            self.current_file = file_path
            
            # Actualizar UI
            self.load_wallet_list()
            self.update_wallet_info()
            self.stacked_widget.setCurrentIndex(0)
            
            QMessageBox.information(
                self, 
                "Éxito", 
                "Billetera creada y cargada correctamente!\n\n" +
                f"Archivo: {os.path.basename(file_path)}\n" +
                f"Dirección: {wallet.address}"
            )
            
        except Exception as e:
            logger.error(f"Error en on_wallet_created: {str(e)}")
            QMessageBox.critical(self, "Error", f"No se pudo cargar la billetera: {str(e)}")
        finally:
            self.show_loading(False)
            self.cleanup_workers()

    

    def on_wallet_create_error(self, error):
        """Maneja errores del worker de creación"""
        logger.error(f"Error al crear wallet: {error}")
        self.show_loading(False)
        QMessageBox.critical(self, "Error", f"No se pudo crear la billetera: {error}")
        self.cleanup_workers()

    def show_password_error(self, message):
        """Muestra un mensaje de error de contraseña"""
        logger.warning(f"Error en contraseña: {message}")
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Warning)
        msg.setWindowTitle("Error en Contraseña")
        msg.setText(message)
        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec_()
    
    def load_wallet(self):
        """Carga una wallet desde archivo y actualiza la lista izquierda"""
        self.update_last_activity()
        logger.debug("Iniciando carga de wallet")
        
        try:
            # 1. Diálogo para seleccionar archivo
            file_path, _ = QFileDialog.getOpenFileName(
                self, "Abrir Billetera", 
                "", "Billetera Cripto (*.cwallet)"
            )
            
            if not file_path:
                logger.debug("Usuario canceló selección de archivo")
                return
                
            file_path = os.path.abspath(file_path)
            logger.debug(f"Archivo seleccionado: {file_path}")

            # 2. Verificar si ya está en la lista
            if file_path in self.wallet_manager.wallet_files:
                logger.debug("Wallet ya existe en la lista, seleccionando...")
                self._select_wallet_in_list(file_path)
                return

            # 3. Diálogo de contraseña
            password = self._get_wallet_password(file_path)
            if not password:
                return

            # 4. Cargar wallet en segundo plano
            self._load_wallet_in_background(file_path, password)
            
        except Exception as e:
            logger.error(f"Error en load_wallet: {str(e)}")
            QMessageBox.critical(self, "Error", f"Error al cargar: {str(e)}")

    def _load_wallet_in_background(self, file_path, password):
        """Inicia el proceso de carga en segundo plano"""
        self.show_loading("Cargando billetera...")
        
        # Worker para descifrado
        worker = Worker(self.wallet_manager.decrypt_wallet, file_path, password)
        worker.finished.connect(lambda w: self._finalize_wallet_load(w, file_path))
        worker.error.connect(self._handle_load_error)
        self.active_workers.append(worker)
        worker.start()

    def _finalize_wallet_load(self, wallet, file_path):
        """Completa el proceso de carga del wallet"""
        try:
            logger.debug(f"Finalizando carga de wallet: {file_path}")
            
            # 1. Establecer wallet actual
            self.current_wallet = wallet
            self.current_file = file_path
            
            # 2. Agregar a la lista si no existe (REQUISITO PRINCIPAL)
            if file_path not in self.wallet_manager.wallet_files:
                self.wallet_manager.wallet_files.append(file_path)
                self.wallet_manager.save_config()
                logger.debug(f"Wallet agregado a la lista: {file_path}")

            # 3. Actualizar lista visual
            self._update_wallet_list()
            
            # 4. Seleccionar en la lista
            self._select_existing_wallet(file_path)
            
            # 5. Actualizar UI principal - ADDED THIS SECTION
            self.address_label.setText(wallet.address)
            self.generate_qr_code(wallet.address)
            self.update_wallet_info()
            self.stacked_widget.setCurrentIndex(0)
            
            # 6. Verificar si existe archivo de transacciones - ADDED THIS SECTION
            parquet_file = f"txs_{wallet.address[:6]}.parquet"
            if os.path.exists(parquet_file):
                try:
                    df = pd.read_parquet(parquet_file)
                    self.current_wallet._tx_dataframe = df
                    self.update_tx_tables_from_df()
                    logger.info(f"Historial cargado desde archivo {parquet_file}")
                except Exception as e:
                    logger.error(f"Error cargando transacciones desde archivo: {str(e)}")
            
            # 7. Sincronizar en segundo plano sin bloquear la UI - ADDED THIS SECTION
            self.show_loading_message("Sincronizando transacciones en segundo plano...")
            worker = Worker(self.sync_and_update_transactions)
            worker.finished.connect(lambda: self.show_loading(False))
            worker.error.connect(lambda e: logger.error(f"Error sincronizando: {e}"))
            self.active_workers.append(worker)
            worker.start()
            
            logger.debug("Wallet cargado y mostrado correctamente")
            
        except Exception as e:
            logger.error(f"Error en _finalize_wallet_load: {str(e)}")
            QMessageBox.critical(self, "Error", f"Error al finalizar carga: {str(e)}")
        finally:
            self.show_loading(False)
            
    def _update_wallet_display(self, wallet):
        """Actualiza los componentes visuales principales"""
        self.address_label.setText(wallet.address)
        self.generate_qr_code(wallet.address)
        self.update_wallet_info()
        self.stacked_widget.setCurrentIndex(0)

    def _handle_load_error(self, error_msg):
        """Maneja errores durante la carga"""
        logger.error(f"Error cargando wallet: {error_msg}")
        self.show_loading(False)
        
        user_msg = "Contraseña incorrecta" if "decrypt" in str(error_msg).lower() else f"Error: {str(error_msg)}"
        QMessageBox.warning(self, "Error al cargar", user_msg)

    def _update_wallet_list(self):
        """Actualiza completamente la lista visual de wallets"""
        self.wallet_list.clear()
        
        for wallet_file in self.wallet_manager.wallet_files:
            try:
                item = QListWidgetItem(os.path.basename(wallet_file))
                item.setData(Qt.UserRole, wallet_file)
                
                # Configurar icono según si es el wallet actual
                if wallet_file == self.current_file:
                    item.setIcon(QIcon(":/icons/wallet_active.png"))
                    item.setBackground(QColor('#E3F2FD'))
                else:
                    item.setIcon(QIcon(":/icons/wallet.png"))
                    
                item.setToolTip(wallet_file)  # Mostrar ruta completa
                self.wallet_list.addItem(item)
                
            except Exception as e:
                logger.error(f"Error agregando wallet a lista: {str(e)}")

    def _get_wallet_icon(self, file_path):
        """Devuelve icono según si es la wallet actual"""
        if self.current_file == file_path:
            return QIcon(":/icons/wallet_active.png")
        return QIcon(":/icons/wallet.png")


    def _get_wallet_display_name(self, file_path):
        """Genera nombre amigable para mostrar"""
        base_name = os.path.basename(file_path)
        if base_name.endswith('.cwallet'):
            base_name = base_name[:-8]
        
        # Si es la wallet actual, mostrar dirección abreviada
        if self.current_file == file_path and self.current_wallet:
            return f"{base_name} ({self.current_wallet.address[:6]}...)"
        return base_name
    
    def _select_wallet_in_list(self, file_path):
        """Selecciona un wallet existente en la lista izquierda"""
        for i in range(self.wallet_list.count()):
            item = self.wallet_list.item(i)
            if item.data(Qt.UserRole) == file_path:
                self.wallet_list.setCurrentItem(item)
                item.setSelected(True)
                self.wallet_list.scrollToItem(item)
                break
    
    def _get_wallet_password(self, file_path):
        #"""Muestra diálogo para obtener contraseña"""
        password_dialog = QInputDialog(self)
        password_dialog.setWindowTitle("Contraseña Requerida")
        password_dialog.setLabelText(f"Contraseña para {os.path.basename(file_path)}:")
        password_dialog.setTextEchoMode(QLineEdit.Password)
        password_dialog.setFixedSize(400, 150)
        
        if password_dialog.exec_() == QDialog.Accepted:
            return password_dialog.textValue()
        return None

    def _select_existing_wallet(self, file_path):
        """Selecciona un wallet existente en la lista izquierda"""
        for i in range(self.wallet_list.count()):
            item = self.wallet_list.item(i)
            if item.data(Qt.UserRole) == file_path:
                self.wallet_list.setCurrentItem(item)
                item.setSelected(True)
                self.wallet_list.scrollToItem(item)
                break
            
    def on_wallet_loaded(self, wallet, file_path):
        """Maneja la carga exitosa de una wallet"""
        logger.debug(f"Wallet cargado exitosamente: {file_path}")
        self.show_loading(False)
        self.current_wallet = wallet
        self.current_file = file_path
        
        # Mostrar información básica inmediatamente
        self.address_label.setText(wallet.address)
        self.generate_qr_code(wallet.address)
        
        # Actualizar balances en segundo plano
        self.update_wallet_info()
        
        # Verificar si existe archivo de transacciones
        parquet_file = f"txs_{wallet.address[:6]}.parquet"
        if os.path.exists(parquet_file):
            try:
                df = pd.read_parquet(parquet_file)
                self.current_wallet._tx_dataframe = df
                self.update_tx_tables_from_df()
                logger.info(f"Historial cargado desde archivo {parquet_file}")
            except Exception as e:
                logger.error(f"Error cargando transacciones desde archivo: {str(e)}")
        
        # Sincronizar en segundo plano sin bloquear la UI
        self.show_loading_message("Sincronizando transacciones en segundo plano...")
        worker = Worker(self.sync_and_update_transactions)
        worker.finished.connect(lambda: self.show_loading(False))
        worker.error.connect(lambda e: logger.error(f"Error sincronizando: {e}"))
        self.active_workers.append(worker)
        worker.start()
        
        self.stacked_widget.setCurrentIndex(0)

    def sync_and_update_transactions(self):
        """Sincroniza transacciones y actualiza UI"""
        if hasattr(self, 'current_wallet') and self.current_wallet:
            try:
                # Obtener todas las transacciones sin límite
                df = self.current_wallet.sync_all_transactions(start_block=1)
                
                if df is None or df.empty:
                    logger.warning("No se obtuvieron transacciones de la API")
                    return
                    
                # Filtrar transacciones con valor <= 0.000000
                df = df[df['value'] > 0.000000]
                
                # Asegurar que el timestamp sea numérico
                if 'timestamp' in df.columns:
                    df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s', errors='coerce')
                
                # Guardar DataFrame en el wallet
                self.current_wallet._tx_dataframe = df
                
                # Actualizar todas las tablas
                self.update_tx_tables_from_df()
                
            except Exception as e:
                logger.error(f"Error en sync_and_update_transactions: {str(e)}")
                self.show_loading(False)

    def on_wallet_load_error(self, error):
        """Maneja errores al cargar una wallet"""
        logger.error(f"Error al cargar wallet: {error}")
        self.show_loading(False)
        QMessageBox.critical(self, "Error", f"No se pudo cargar la billetera: {error}")
        self.cleanup_workers()

    def select_wallet(self, item):
        """Selecciona una wallet de la lista"""
        self.update_last_activity()
        file_path = item.data(Qt.UserRole)
        
        # Resaltar visualmente el ítem seleccionado
        for i in range(self.wallet_list.count()):
            self.wallet_list.item(i).setSelected(False)
        item.setSelected(True)

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
        """Maneja la selección exitosa de una wallet"""
        self.show_loading(False)
        self.current_wallet = wallet
        self.current_file = file_path
        
        # Mostrar información básica inmediatamente
        self.address_label.setText(wallet.address)
        self.generate_qr_code(wallet.address)
        
        # Actualizar balances en segundo plano
        self.update_wallet_info()
        
        # Verificar si existe archivo de transacciones
        parquet_file = f"txs_{wallet.address[:6]}.parquet"
        if os.path.exists(parquet_file):
            try:
                df = pd.read_parquet(parquet_file)
                self.current_wallet._tx_dataframe = df
                self.update_tx_tables_from_df()
                logger.info(f"Historial cargado desde archivo {parquet_file}")
            except Exception as e:
                logger.error(f"Error cargando transacciones desde archivo: {str(e)}")
        
        # Sincronizar en segundo plano sin bloquear la UI
        self.show_loading_message("Sincronizando transacciones en segundo plano...")
        worker = Worker(self.sync_and_update_transactions)
        worker.finished.connect(lambda: self.show_loading(False))
        worker.error.connect(lambda e: logger.error(f"Error sincronizando: {e}"))
        self.active_workers.append(worker)
        worker.start()
        
        self.stacked_widget.setCurrentIndex(0)

    def on_wallet_select_error(self, error):
        """Maneja errores al seleccionar una wallet"""
        logger.error(f"Error al seleccionar wallet: {error}")
        self.show_loading(False)
        QMessageBox.critical(self, "Error", f"No se pudo cargar la billetera: {error}")
        self.cleanup_workers()

    def update_wallet_info(self):
        """Actualiza la información básica del wallet (balances)"""
        if not self.current_wallet:
            self.show_empty_state()
            return
            
        self.show_wallet_state()
        self.address_label.setText(self.current_wallet.address)
        self.generate_qr_code(self.current_wallet.address)
        
        # Actualizar balances
        worker = Worker(self._fetch_wallet_balances)
        worker.finished.connect(self._update_balances_ui)
        worker.error.connect(lambda e: logger.error(f"Error actualizando balances: {e}"))
        self.active_workers.append(worker)
        worker.start()

    def _fetch_wallet_balances(self):
        """Obtiene los balances del wallet en un worker"""
        return {
            'BNB': self.current_wallet.get_balance('BNB'),
            'USDT': self.current_wallet.get_balance('USDT'),
            'USDC': self.current_wallet.get_balance('USDC')
        }

    def _update_balances_ui(self, balances):
        """Actualiza la UI con los balances obtenidos"""
        try:
            self.bnb_balance.setText(f"{balances['BNB']:.6f}" if balances['BNB'] is not None else "Error")
            self.usdt_balance.setText(f"{balances['USDT']:.6f}" if balances['USDT'] is not None else "Error")
            self.usdc_balance.setText(f"{balances['USDC']:.6f}" if balances['USDC'] is not None else "Error")
            
            # Actualizar columna de balance en la tabla de resumen
            for row in range(self.summary_table.rowCount()):
                token = self.summary_table.item(row, 0).text()
                if token in balances:
                    balance = balances[token]
                    item = QTableWidgetItem(f"{balance:.6f}" if balance is not None else "N/A")
                    self.summary_table.setItem(row, 4, item)
        except Exception as e:
            logger.error(f"Error en _update_balances_ui: {str(e)}")
            
    def update_tx_tables_from_df(self):
        """Actualiza la tabla de resumen con todas las transacciones mezcladas"""
        if not hasattr(self, 'current_wallet') or not hasattr(self.current_wallet, '_tx_dataframe'):
            self._show_no_transactions_message()
            return
                
        df = self.current_wallet._tx_dataframe
        
        if df.empty:
            self._show_no_transactions_message()
            return
        
        # Filtrar transacciones con valor > 0.000000
        df = df[df['value'] > 0.000000]
        
        # Ordenar por fecha descendente
        df = df.sort_values('timestamp', ascending=False)
        
        # Configurar tabla
        self.summary_table.setRowCount(len(df))
        
        for row, tx in df.iterrows():
            # Fecha
            date_str = tx['timestamp'].strftime("%Y-%m-%d %H:%M") if not pd.isna(tx['timestamp']) else "N/A"
            self.summary_table.setItem(row, 0, QTableWidgetItem(date_str))
            
            # Moneda (BNB, USDT, USDC)
            token_item = QTableWidgetItem(tx.get('token', 'N/A'))
            self.summary_table.setItem(row, 1, token_item)
            
            # Tipo (Entrada/Salida)
            direction = "Entrada" if tx.get('direction') == 'in' else "Salida"
            type_item = QTableWidgetItem(direction)
            type_item.setForeground(QColor('#4CAF50' if direction == "Entrada" else '#F44336'))
            self.summary_table.setItem(row, 2, type_item)
            
            # Valor
            value = tx.get('value', 0)
            value_item = QTableWidgetItem(f"{value:.6f}")
            value_item.setForeground(QColor('#4CAF50' if direction == "Entrada" else '#F44336'))
            self.summary_table.setItem(row, 3, value_item)
            
            # Contraparte
            counterparty = tx['from'] if direction == "Entrada" else tx['to']
            self.summary_table.setItem(row, 4, QTableWidgetItem(counterparty))
            
            # Hash
            hash_item = QTableWidgetItem(tx.get('hash', 'N/A'))
            hash_item.setToolTip(tx.get('hash', ''))  # Tooltip con hash completo
            self.summary_table.setItem(row, 5, hash_item)
            
            # Estado
            status = tx.get('status', 'confirmed')
            status_item = QTableWidgetItem(status.capitalize())
            if status.lower() == 'failed':
                status_item.setForeground(QColor('#F44336'))
            self.summary_table.setItem(row, 6, status_item)
        
        # Mostrar la tabla u ocultarla si está vacía
        if len(df) > 0:
            self.summary_table.show()
            self.no_tx_label.hide()
            self.summary_table.resizeColumnsToContents()
        else:
            self._show_no_transactions_message()

    
    def _show_no_transactions_message(self):
        """Muestra mensaje cuando no hay transacciones"""
        self.summary_table.hide()
        self.no_tx_label.setText("No hay transacciones disponibles")
        self.no_tx_label.show()
            
    def _update_token_tab(self, token, df):
        """Actualiza la pestaña de un token específico con todos los datos de la API"""
        if df.empty:
            logger.warning(f"No hay datos para el token {token}")
            return
            
        # Convertir timestamp a datetime si es necesario
        if not pd.api.types.is_datetime64_any_dtype(df['timestamp']):
            df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s', errors='coerce')
        
        # Ordenar por timestamp descendente (más reciente primero)
        df = df.sort_values('timestamp', ascending=False)
        
        # Obtener referencia a la tabla
        table = getattr(self, f"{token.lower()}_tx_table")
        table.setRowCount(len(df))
        
        # Configurar scroll vertical
        table.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
        
        # Llenar la tabla con todos los datos
        for row, tx in df.iterrows():
            # Fecha formateada
            date_str = tx['timestamp'].strftime("%Y-%m-%d %H:%M") if not pd.isna(tx['timestamp']) else "Fecha desconocida"
            
            # Dirección (mostrar completa)
            address = self.current_wallet.address.lower()
            direction = "Entrada" if str(tx['to']).lower() == address else "Salida"
            counterparty = tx['from'] if direction == "Entrada" else tx['to']
            
            # Valor formateado
            value = tx.get('value', 0)
            value_str = f"{value:.6f}" if value is not None else "N/A"
            
            # Estado
            status = tx.get('status', 'confirmed') if 'status' in tx else 'confirmed'
            
            # Llenar las celdas
            table.setItem(row, 0, QTableWidgetItem(date_str))
            
            type_item = QTableWidgetItem(direction)
            type_item.setForeground(QColor('#4CAF50' if direction == "Entrada" else '#F44336'))
            table.setItem(row, 1, type_item)
            
            value_item = QTableWidgetItem(value_str)
            value_item.setForeground(QColor('#4CAF50' if direction == "Entrada" else '#F44336'))
            table.setItem(row, 2, value_item)
            
            table.setItem(row, 3, QTableWidgetItem(counterparty))
            table.setItem(row, 4, QTableWidgetItem(tx.get('hash', 'N/A')))
            table.setItem(row, 5, QTableWidgetItem(status))
        
        # Ajustar el tamaño de las columnas al contenido
        table.resizeColumnsToContents()
        
        # Mostrar mensaje de debug con los primeros 5 registros
        logger.debug(f"Mostrando {len(df)} transacciones para {token}. Primeras 5:")
        logger.debug(df.head().to_string())


    def _handle_chart_update(self, token, df):
        """Maneja la actualización del gráfico desde la señal"""
        try:
            if not hasattr(self, 'current_wallet') or not hasattr(self.current_wallet, '_tx_dataframe'):
                return
                
            address = self.current_wallet.address.lower()
            chart_view = getattr(self, f"{token.lower()}_tx_chart")
            
            # Filtrar transacciones del token específico
            token_df = df[df['token'] == token].copy()
            
            if token_df.empty:
                return
                
            # Asegurar que la columna 'timestamp' sea tipo datetime
            token_df['timestamp'] = pd.to_datetime(token_df['timestamp'], errors='coerce')
            token_df = token_df.sort_values('timestamp')
            
            # Separar entradas y salidas
            incoming = token_df[token_df['to'].str.lower() == address]
            outgoing = token_df[token_df['from'].str.lower() == address]
            
            # Series acumulativas
            incoming_cum = incoming['value'].cumsum()
            outgoing_cum = outgoing['value'].cumsum()
            
            # Crear nuevo gráfico
            chart = QChart()
            chart.setTitle(f"Historial de {token}")
            chart.setAnimationOptions(QChart.SeriesAnimations)
            
            # Serie de entradas
            incoming_series = QLineSeries()
            incoming_series.setName("Entradas")
            incoming_series.setColor(QColor('#4CAF50'))
            
            # Serie de salidas
            outgoing_series = QLineSeries()
            outgoing_series.setName("Salidas")
            outgoing_series.setColor(QColor('#F44336'))
            
            # Agregar datos a las series
            for ts, val in zip(incoming['timestamp'], incoming_cum):
                incoming_series.append(ts.timestamp() * 1000, val)
                
            for ts, val in zip(outgoing['timestamp'], outgoing_cum):
                outgoing_series.append(ts.timestamp() * 1000, val)
            
            chart.addSeries(incoming_series)
            chart.addSeries(outgoing_series)
            
            # Configurar ejes
            axis_x = QDateTimeAxis()
            axis_x.setFormat("dd MMM yyyy")
            axis_x.setTitleText("Fecha")
            
            if not token_df.empty:
                start = QDateTime(token_df['timestamp'].min())
                end = QDateTime(token_df['timestamp'].max())
                axis_x.setRange(start, end)
            
            axis_y = QValueAxis()
            axis_y.setTitleText("Valor")
            max_val = max(incoming_cum.max() if not incoming_cum.empty else 0,
                        outgoing_cum.max() if not outgoing_cum.empty else 0)
            axis_y.setRange(0, max_val * 1.1)
            
            chart.addAxis(axis_x, Qt.AlignBottom)
            chart.addAxis(axis_y, Qt.AlignLeft)
            
            incoming_series.attachAxis(axis_x)
            incoming_series.attachAxis(axis_y)
            outgoing_series.attachAxis(axis_x)
            outgoing_series.attachAxis(axis_y)
            
            # Limpiar gráfico anterior y establecer el nuevo
            chart_view.setChart(chart)
            
        except Exception as e:
            logger.error(f"Error en _handle_chart_update: {str(e)}")

    def _update_token_chart(self, token, df):
        """Actualiza el gráfico para un token específico mostrando balance acumulado"""
        if QThread.currentThread() != QApplication.instance().thread():
            QTimer.singleShot(0, lambda: self._update_token_chart(token, df))
            return
            
        chart_view = getattr(self, f"{token.lower()}_tx_chart")
        address = self.current_wallet.address.lower()

        if df.empty:
            return

        # Asegurar que la columna 'timestamp' sea tipo datetime
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        df_sorted = df.sort_values('timestamp')

        # Calcular balance acumulado
        df_sorted['delta'] = df_sorted.apply(
            lambda x: x['value'] if x['direction'] == 'in' else -x['value'], 
            axis=1
        )
        df_sorted['balance'] = df_sorted['delta'].cumsum()

        # Crear gráfico en el hilo principal
        chart = QChart()
        chart.setTitle(f"Evolución de Balance - {token}")
        chart.setAnimationOptions(QChart.SeriesAnimations)
        chart.legend().setVisible(True)
        chart.legend().setAlignment(Qt.AlignBottom)

        # Serie de balance
        balance_series = QLineSeries()
        balance_series.setName("Balance")
        balance_series.setColor(QColor('#4e9af1'))
        
        # Agregar puntos de transacción
        for _, tx in df_sorted.iterrows():
            balance_series.append(tx['timestamp'].timestamp() * 1000, tx['balance'])
            
            # Agregar marcadores para transacciones importantes
            if abs(tx['delta']) > 0.1:  # Solo marcar transacciones significativas
                marker = QScatterSeries()
                marker.setName(f"Tx {tx['hash'][:6]}")
                marker.setMarkerSize(10)
                marker.setColor(QColor('#4CAF50' if tx['delta'] > 0 else '#F44336'))
                marker.append(tx['timestamp'].timestamp() * 1000, tx['balance'])
                chart.addSeries(marker)

        chart.addSeries(balance_series)

        # Configurar ejes
        axis_x = QDateTimeAxis()
        axis_x.setFormat("dd MMM yyyy")
        axis_x.setTitleText("Fecha")
        
        if not df_sorted.empty:
            start = QDateTime(df_sorted['timestamp'].min())
            end = QDateTime(df_sorted['timestamp'].max())
            axis_x.setRange(start, end)

        axis_y = QValueAxis()
        axis_y.setTitleText("Balance")
        min_val = df_sorted['balance'].min() * 0.9 if df_sorted['balance'].min() < 0 else 0
        max_val = df_sorted['balance'].max() * 1.1
        axis_y.setRange(min_val, max_val)

        chart.addAxis(axis_x, Qt.AlignBottom)
        chart.addAxis(axis_y, Qt.AlignLeft)

        balance_series.attachAxis(axis_x)
        balance_series.attachAxis(axis_y)
        
        # Configurar tooltips
        tooltip = QToolTip()
        tooltip.setFont(QFont("Arial", 10))
        chart.setToolTip("Haz clic en los puntos para ver detalles")

        chart_view.setChart(chart)
        chart_view.setRenderHint(QPainter.Antialiasing)
            
            
    def generate_qr_code(self, address):
        """Genera y muestra un QR code para la dirección del wallet"""
        try:
            qr_pixmap = self.current_wallet.generate_qr_code(address)
            self.qr_code_label.setPixmap(qr_pixmap)
        except Exception as e:
            logger.error(f"Error generando QR code: {str(e)}")
            self.qr_code_label.clear()
            self.qr_code_label.setText("Error generando QR")
            self.qr_code_label.setStyleSheet("color: red; font-weight: bold;")

    def _calculate_optimal_gas(self, token_symbol='BNB'):
        """
        Calcula los parámetros óptimos de gas
        
        Args:
            token_symbol (str): Símbolo del token para calcular gas apropiado
            
        Returns:
            dict: {'gas_price': float, 'gas_limit': int, 'speed': str}
        """
        try:
            current_gas = float(self.web3.from_wei(
                self.web3.eth.gas_price, 
                'gwei'
            ))
            
            # Valores conservadores para BSC
            gas_params = {
                'low': max(1.0, current_gas * 0.8),
                'medium': max(3.0, current_gas * 1.0),
                'high': max(5.0, current_gas * 1.3),
                'urgent': max(10.0, current_gas * 2.0),
            }
            
            return {
                'gas_price': gas_params['medium'],
                'gas_limit': 21000 if token_symbol == 'BNB' else 100000,
                'speed': 'medium'
            }
            
        except Exception:
            # Valores por defecto seguros
            return {
                'gas_price': 3.0,
                'gas_limit': 21000 if token_symbol == 'BNB' else 100000,
                'speed': 'medium'
            }

    def send_transaction(self, recipient, amount, token_symbol='BNB', gas_price=None, gas_limit=None, retries=3):
        """
        Envía una transacción con manejo de errores y reintentos
        
        Args:
            recipient (str): Dirección del destinatario
            amount (float): Cantidad a enviar
            token_symbol (str): Símbolo del token ('BNB', 'USDT', 'USDC')
            gas_price (float, optional): Precio de gas en gwei. Si es None, se calcula automáticamente.
            gas_limit (int, optional): Límite de gas. Si es None, se usa valor por defecto.
            retries (int): Número de reintentos en caso de fallo
            
        Returns:
            str: Hash de la transacción
            
        Raises:
            Exception: Si la transacción falla después de todos los reintentos
        """
        for attempt in range(retries):
            try:
                # Validaciones iniciales
                if token_symbol not in self.TOKEN_CONTRACTS:
                    raise ValueError(f"Token no soportado: {token_symbol}")
                    
                recipient = Web3.to_checksum_address(recipient)
                
                # Configuración de gas si no se especifica
                if gas_price is None or gas_limit is None:
                    gas_params = self._calculate_optimal_gas(token_symbol)
                    gas_price = gas_params['gas_price']
                    gas_limit = gas_params['gas_limit']
                
                # Transacción de BNB
                if token_symbol == 'BNB':
                    tx_params = {
                        'to': recipient,
                        'value': self.web3.to_wei(amount, 'ether'),
                        'gas': gas_limit,
                        'gasPrice': self.web3.to_wei(gas_price, 'gwei'),
                        'nonce': self.web3.eth.get_transaction_count(self.address),
                        'chainid': 56  # BSC chain ID
                    }
                    
                    signed_tx = self.web3.eth.account.sign_transaction(tx_params, self.private_key)
                    tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
                
                # Transacción de token
                else:
                    contract = self.web3.eth.contract(
                        address=self.TOKEN_CONTRACTS[token_symbol],
                        abi=self._get_erc20_abi()
                    )
                    
                    amount_wei = int(amount * (10 ** self.TOKEN_DECIMALS[token_symbol]))
                    
                    tx_params = {
                        'gas': gas_limit,
                        'gasPrice': self.web3.to_wei(gas_price, 'gwei'),
                        'nonce': self.web3.eth.get_transaction_count(self.address),
                        'chainId': 56
                    }
                    
                    tx = contract.functions.transfer(recipient, amount_wei).build_transaction(tx_params)
                    signed_tx = self.web3.eth.account.sign_transaction(tx, self.private_key)
                    tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
                
                # Limpiar cachés después de enviar
                self._clear_caches()
                
                return tx_hash.hex()
                
            except Exception as e:
                if attempt == retries - 1:
                    raise Exception(f"Error después de {retries} intentos: {str(e)}")
                time.sleep(2 ** attempt)  # Backoff exponencial



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

    def show_loading(self, show=True, message="Cargando..."):
        """Muestra u oculta el indicador de carga con mensaje personalizable"""
        if show:
            self.loading_widget.text_label.setText(message)
            self.stacked_widget.setCurrentIndex(1)
        else:
            self.stacked_widget.setCurrentIndex(0)
        QApplication.processEvents()  # Forzar actualización de la UI
    
    def show_loading_message(self, message):
        """Muestra un mensaje de carga personalizado"""
        self.loading_widget.text_label.setText(message)
        self.stacked_widget.setCurrentIndex(1)
    
    def update_last_activity(self):
        """Actualiza el tiempo de última actividad"""
        self.last_activity = datetime.now()
    
    def check_session(self):
        """Verifica si la sesión ha expirado por inactividad"""
        if self.current_wallet and (datetime.now() - self.last_activity).total_seconds() > SESSION_TIMEOUT * 60:
            logger.info("Sesión expirada por inactividad")
            QMessageBox.information(self, "Sesión expirada", "Su sesión ha expirado por inactividad.")
            self.logout()
    
    def logout(self):
        """Cierra la sesión del wallet actual"""
        logger.debug("Cerrando sesión")
        self.current_wallet = None
        self.current_file = None
        self.show_empty_state()
        self.last_activity = datetime.now()
        
    def cleanup_workers(self):
        """Limpia los workers terminados"""
        for worker in self.active_workers[:]:  # Usamos copia para iterar
            if worker.isFinished():
                try:
                    logger.debug(f"Limpiando worker {id(worker)}")
                    worker.quit()
                    worker.wait()
                    worker.deleteLater()
                    self.active_workers.remove(worker)
                except Exception as e:
                    logger.error(f"Error limpiando worker {id(worker)}: {str(e)}")

    def show_connectivity_error(self):
        """Muestra error de conectividad"""
        QMessageBox.critical(
            self, 
            "Sin conexión", 
            "No se puede conectar a internet. Esta operación requiere conexión a la red."
        )


    def center_on_screen(self):
        """Centra la ventana en la pantalla"""
        frame_geometry = self.frameGeometry()
        center_point = QApplication.desktop().availableGeometry().center()
        frame_geometry.moveCenter(center_point)
        self.move(frame_geometry.topLeft())

    def closeEvent(self, event):
        """Maneja el cierre de la aplicación de forma segura"""
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

def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    # Precargar recursos para mejor rendimiento
    QIcon(":/icons/solidwallet.png")
    QIcon(":/icons/info.svg")
    QIcon(":/icons/history.svg")
    QIcon(":/icons/send.svg")
    QIcon(":/icons/settings.svg")
    QIcon(":/icons/warning.svg")
    
    window = SolidWalletGUI()
    window.show()
    
    try:
        sys.exit(app.exec_())
    except Exception as e:
        logger.critical(f"Error fatal en la aplicación: {e}")
        raise

if __name__ == "__main__":
    main()
