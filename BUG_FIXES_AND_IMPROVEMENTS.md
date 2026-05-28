# HoneyTrack - Bug Fixes and Production Improvements

## 🔴 CRITICAL BUGS TO FIX

---

## **BUG #1: setup_db.py - Hardcoded Credentials**

### ❌ Current Code (Lines 14-18):
```python
conn = mysql.connector.connect(
    host='localhost',
    user='root',
    password=''
)
```

### ✅ Fixed Code:
```python
import os
from dotenv import load_dotenv

load_dotenv()

conn = mysql.connector.connect(
    host=os.getenv('DB_HOST', 'localhost'),
    port=int(os.getenv('DB_PORT', 3306)),
    user=os.getenv('DB_USER', 'root'),
    password=os.getenv('DB_PASSWORD', ''),
    charset='utf8mb4'
)
```

### Why: Security risk - credentials should come from .env, not hardcoded

---

## **BUG #2: database/db_manager.py - No Connection Check**

### ❌ Current Code (Lines 42-52):
```python
def execute(self, query: str, params: tuple = ()) -> bool:
    try:
        cursor = self.connection.cursor()  # ❌ May be None!
        cursor.execute(query, params)
        self.connection.commit()
        cursor.close()
        return True
    except Exception as e:
        logger.error(f"Query execution failed: {e}")
        return False
```

### ✅ Fixed Code:
```python
def execute(self, query: str, params: tuple = ()) -> bool:
    """Execute query with connection check"""
    if not self.connection:
        logger.error("Database not connected - cannot execute query")
        return False
    
    try:
        cursor = self.connection.cursor()
        cursor.execute(query, params)
        self.connection.commit()
        cursor.close()
        return True
    except Exception as e:
        logger.error(f"Query execution failed: {e}")
        return False

def fetch_one(self, query: str, params: tuple = ()) -> Optional[tuple]:
    """Fetch one row with connection check"""
    if not self.connection:
        logger.error("Database not connected - cannot fetch")
        return None
    
    try:
        cursor = self.connection.cursor()
        cursor.execute(query, params)
        result = cursor.fetchone()
        cursor.close()
        return result
    except Exception as e:
        logger.error(f"Fetch failed: {e}")
        return None

def fetch_all(self, query: str, params: tuple = ()) -> List[tuple]:
    """Fetch all rows with connection check"""
    if not self.connection:
        logger.error("Database not connected - cannot fetch")
        return []
    
    try:
        cursor = self.connection.cursor()
        cursor.execute(query, params)
        result = cursor.fetchall()
        cursor.close()
        return result
    except Exception as e:
        logger.error(f"Fetch failed: {e}")
        return []
```

### Why: Prevents crashes when database is not connected

---

## **BUG #3: main.py - Unsafe Shutdown**

### ❌ Current Code (Lines 176-185):
```python
if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        ssh_honeypot.stop()      # ❌ May fail if not initialized
        http_honeypot.stop()     # ❌ May fail if not initialized
        if db:
            db.disconnect()
        sys.exit(0)
```

### ✅ Fixed Code:
```python
if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        
        # Safe shutdown
        try:
            if ssh_honeypot and hasattr(ssh_honeypot, 'running') and ssh_honeypot.running:
                ssh_honeypot.stop()
                logger.info("SSH Honeypot stopped")
        except Exception as e:
            logger.error(f"Error stopping SSH Honeypot: {e}")
        
        try:
            if http_honeypot and hasattr(http_honeypot, 'running') and http_honeypot.running:
                http_honeypot.stop()
                logger.info("HTTP Honeypot stopped")
        except Exception as e:
            logger.error(f"Error stopping HTTP Honeypot: {e}")
        
        try:
            if db:
                db.disconnect()
                logger.info("Database disconnected")
        except Exception as e:
            logger.error(f"Error disconnecting database: {e}")
        
        logger.info("Shutdown complete")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)
```

### Why: Prevents crashes during shutdown

---

## **BUG #4: mitre/mitre_mapper.py - Wrong Attack Type Mapping**

### ❌ Current Code (Lines 69-80):
```python
def map_ssh_attack(self, ssh_data):
    attack_type = 'Reconnaissance'
    
    # Check for brute force
    if ssh_data.get('failed_attempts', 0) > 5:
        attack_type = 'Credential Access'
        mapping = self.db.get_attack_mapping('Fuzzers')  # ❌ Wrong!
```

### ✅ Fixed Code:
```python
def map_ssh_attack(self, ssh_data):
    """Map SSH attack to MITRE framework"""
    attack_type = 'Reconnaissance'
    
    # Check for brute force
    if ssh_data.get('failed_attempts', 0) > 5:
        attack_type = 'Credential Access'
        mapping = self.db.get_attack_mapping('Credential Access')  # ✓ Correct!
    else:
        mapping = self.db.get_attack_mapping(attack_type)
    
    return {
        'source': 'SSH',
        'attack_type': attack_type,
        'source_ip': ssh_data.get('source_ip'),
        'username': ssh_data.get('username'),
        'failed_attempts': ssh_data.get('failed_attempts', 0),
        'mitre_mapping': mapping,
        'mapped_at': datetime.now().isoformat()
    }
```

### Why: Correct MITRE mapping is essential for threat analysis

---

## **BUG #5: virustotal/vt_client.py - Stub Implementation**

### ❌ Current Code (Lines 13-20):
```python
def check_ip(self, ip):
    """Check IP reputation"""
    return {
        'ip': ip,
        'malicious': 0,
        'suspicious': 0,
        'undetected': 0
    }
```

### ✅ Fixed Code:
```python
import requests
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class VirusTotalClient:
    """VirusTotal API Client"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            'x-apikey': api_key,
            'User-Agent': 'HoneyTrack/1.0'
        }
        self.timeout = 10
    
    def check_ip(self, ip: str) -> Dict[str, Any]:
        """
        Check IP reputation on VirusTotal
        
        Args:
            ip: IP address to check
        
        Returns:
            Dictionary with reputation data
        """
        try:
            # Check if IP is valid
            if not self._is_valid_ip(ip):
                logger.warning(f"Invalid IP address: {ip}")
                return {
                    'ip': ip,
                    'valid': False,
                    'error': 'Invalid IP address'
                }
            
            # Make API request
            url = f"{self.base_url}/ip_addresses/{ip}"
            response = requests.get(
                url,
                headers=self.headers,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                
                return {
                    'ip': ip,
                    'valid': True,
                    'malicious': attributes.get('last_analysis_stats', {}).get('malicious', 0),
                    'suspicious': attributes.get('last_analysis_stats', {}).get('suspicious', 0),
                    'undetected': attributes.get('last_analysis_stats', {}).get('undetected', 0),
                    'harmless': attributes.get('last_analysis_stats', {}).get('harmless', 0),
                    'last_analysis_date': attributes.get('last_analysis_date'),
                    'country': attributes.get('country'),
                    'asn': attributes.get('asn'),
                    'reputation': attributes.get('reputation', 0)
                }
            
            elif response.status_code == 401:
                logger.error("VirusTotal API key is invalid")
                return {
                    'ip': ip,
                    'valid': True,
                    'error': 'Invalid API key',
                    'status_code': 401
                }
            
            elif response.status_code == 404:
                logger.info(f"IP {ip} not found in VirusTotal")
                return {
                    'ip': ip,
                    'valid': True,
                    'malicious': 0,
                    'suspicious': 0,
                    'undetected': 0,
                    'harmless': 0,
                    'status_code': 404
                }
            
            else:
                logger.warning(f"VirusTotal API error: {response.status_code}")
                return {
                    'ip': ip,
                    'valid': True,
                    'error': f'API error: {response.status_code}',
                    'status_code': response.status_code
                }
        
        except requests.Timeout:
            logger.error(f"VirusTotal API timeout for IP: {ip}")
            return {
                'ip': ip,
                'valid': True,
                'error': 'API timeout'
            }
        
        except Exception as e:
            logger.error(f"VirusTotal API error: {str(e)}")
            return {
                'ip': ip,
                'valid': True,
                'error': str(e)
            }
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address"""
        import re
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
        
        return bool(re.match(ipv4_pattern, ip) or re.match(ipv6_pattern, ip))

vt_client = None
```

### Why: Need real API integration for threat intelligence

---

## **BUG #6: ml/predictor.py - Stub Implementation**

### ❌ Current Code (Lines 13-19):
```python
def predict(self, features):
    """Predict attack type"""
    return {
        'prediction': 'Normal',
        'confidence': 0.95,
        'attack_type': None
    }
```

### ✅ Fixed Code:
```python
import logging
import joblib
from pathlib import Path
from typing import Dict, Any, Optional, List
import numpy as np

logger = logging.getLogger(__name__)

class Predictor:
    """ML Predictor for real-time attack classification"""
    
    def __init__(self, model_path: str = 'ml/models'):
        self.model_path = Path(model_path)
        self.models = {}
        self.scaler = None
        self.encoders = None
        self.feature_cols = None
        self.label_encoder = None
        self.load_models()
    
    def load_models(self) -> bool:
        """Load trained models from disk"""
        try:
            # Load scaler
            scaler_file = self.model_path / 'scaler.pkl'
            if scaler_file.exists():
                self.scaler = joblib.load(scaler_file)
                logger.info("✓ Scaler loaded")
            
            # Load encoders
            encoders_file = self.model_path / 'encoders.pkl'
            if encoders_file.exists():
                self.encoders = joblib.load(encoders_file)
                logger.info("✓ Encoders loaded")
            
            # Load feature columns
            feature_cols_file = self.model_path / 'feature_cols.pkl'
            if feature_cols_file.exists():
                self.feature_cols = joblib.load(feature_cols_file)
                logger.info("✓ Feature columns loaded")
            
            # Load label encoder
            label_encoder_file = self.model_path / 'label_encoder.pkl'
            if label_encoder_file.exists():
                self.label_encoder = joblib.load(label_encoder_file)
                logger.info("✓ Label encoder loaded")
            
            # Load models
            models_to_load = [
                ('isolation_forest', 'isolation_forest.pkl'),
                ('rf_binary', 'rf_binary.pkl'),
                ('rf_multiclass', 'rf_multiclass.pkl')
            ]
            
            for model_name, model_file in models_to_load:
                model_path = self.model_path / model_file
                if model_path.exists():
                    self.models[model_name] = joblib.load(model_path)
                    logger.info(f"✓ {model_name} model loaded")
            
            if self.models:
                logger.info(f"✓ All models loaded successfully ({len(self.models)} models)")
                return True
            else:
                logger.warning("⚠ No models found - run training first")
                return False
        
        except Exception as e:
            logger.error(f"Failed to load models: {e}")
            return False
    
    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Predict attack type using loaded models
        
        Args:
            features: Dictionary of features
        
        Returns:
            Prediction result
        """
        if not self.models:
            logger.warning("Models not loaded - returning default prediction")
            return {
                'prediction': 'Unknown',
                'confidence': 0.0,
                'attack_type': None,
                'error': 'Models not loaded'
            }
        
        try:
            # Convert features to array
            feature_array = self._prepare_features(features)
            
            if feature_array is None:
                return {
                    'prediction': 'Unknown',
                    'confidence': 0.0,
                    'attack_type': None,
                    'error': 'Invalid features'
                }
            
            # Isolation Forest (Anomaly Detection)
            anomaly_score = None
            if 'isolation_forest' in self.models:
                anomaly_pred = self.models['isolation_forest'].predict(feature_array)
                anomaly_score = anomaly_pred[0]  # -1 = anomaly, 1 = normal
            
            # Random Forest Binary (Normal vs Attack)
            binary_pred = None
            binary_confidence = 0.0
            if 'rf_binary' in self.models:
                binary_pred = self.models['rf_binary'].predict(feature_array)[0]
                binary_proba = self.models['rf_binary'].predict_proba(feature_array)[0]
                binary_confidence = max(binary_proba)
            
            # Random Forest Multi-class (Attack Type)
            multiclass_pred = None
            multiclass_confidence = 0.0
            if 'rf_multiclass' in self.models and binary_pred == 1:  # Only if attack detected
                multiclass_pred = self.models['rf_multiclass'].predict(feature_array)[0]
                multiclass_proba = self.models['rf_multiclass'].predict_proba(feature_array)[0]
                multiclass_confidence = max(multiclass_proba)
            
            # Decode predictions
            prediction = 'Normal' if binary_pred == 0 else 'Attack'
            attack_type = None
            
            if self.label_encoder and multiclass_pred is not None:
                attack_type = self.label_encoder.inverse_transform([multiclass_pred])[0]
            
            return {
                'prediction': prediction,
                'confidence': float(binary_confidence),
                'attack_type': attack_type,
                'multiclass_confidence': float(multiclass_confidence) if multiclass_confidence else None,
                'anomaly_score': int(anomaly_score) if anomaly_score else None,
                'models_used': list(self.models.keys())
            }
        
        except Exception as e:
            logger.error(f"Prediction error: {e}")
            return {
                'prediction': 'Error',
                'confidence': 0.0,
                'attack_type': None,
                'error': str(e)
            }
    
    def _prepare_features(self, features: Dict[str, Any]) -> Optional[np.ndarray]:
        """Prepare features for prediction"""
        try:
            # This is a placeholder - actual implementation depends on your feature set
            # You need to convert the features dict to the correct format
            
            if not self.feature_cols:
                logger.warning("Feature columns not loaded")
                return None
            
            # Create feature array
            feature_array = np.zeros((1, len(self.feature_cols)))
            
            for i, col in enumerate(self.feature_cols):
                if col in features:
                    feature_array[0, i] = features[col]
            
            # Scale features
            if self.scaler:
                feature_array = self.scaler.transform(feature_array)
            
            return feature_array
        
        except Exception as e:
            logger.error(f"Feature preparation error: {e}")
            return None

predictor = Predictor()
```

### Why: Need actual ML inference with trained models

---

## **BUG #7: ml/honeytrack_ml.py - Stub Implementation**

### ❌ Current Code (Lines 7-10):
```python
def train_models():
    """Train ML models"""
    logger.info("Training models...")
    return True
```

### ✅ Fixed Code:
```python
import logging
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import joblib
import json

logger = logging.getLogger(__name__)

class ModelTrainer:
    """Train ML models on UNSW-NB15 dataset"""
    
    def __init__(self, data_path: str = 'ml/data', model_path: str = 'ml/models'):
        self.data_path = Path(data_path)
        self.model_path = Path(model_path)
        self.model_path.mkdir(parents=True, exist_ok=True)
        
        self.scaler = None
        self.encoders = {}
        self.label_encoder = None
        self.feature_cols = None
    
    def load_data(self) -> tuple:
        """Load UNSW-NB15 dataset"""
        try:
            logger.info("Loading UNSW-NB15 dataset...")
            
            # Load training set
            train_file = self.data_path / 'UNSW_NB15_training-set.csv'
            if not train_file.exists():
                logger.error(f"Training file not found: {train_file}")
                return None, None
            
            X_train = pd.read_csv(train_file)
            logger.info(f"✓ Training set loaded: {X_train.shape}")
            
            # Load test set
            test_file = self.data_path / 'UNSW_NB15_testing-set.csv'
            if not test_file.exists():
                logger.error(f"Test file not found: {test_file}")
                return X_train, None
            
            X_test = pd.read_csv(test_file)
            logger.info(f"✓ Test set loaded: {X_test.shape}")
            
            return X_train, X_test
        
        except Exception as e:
            logger.error(f"Data loading failed: {e}")
            return None, None
    
    def preprocess_data(self, X_train: pd.DataFrame, X_test: pd.DataFrame = None):
        """Preprocess data"""
        try:
            logger.info("Preprocessing data...")
            
            # Separate features and labels
            y_train = X_train['label'] if 'label' in X_train.columns else X_train.iloc[:, -1]
            X_train = X_train.drop(['label'] if 'label' in X_train.columns else X_train.columns[-1], axis=1)
            
            # Store feature columns
            self.feature_cols = X_train.columns.tolist()
            joblib.dump(self.feature_cols, self.model_path / 'feature_cols.pkl')
            
            # Handle categorical features
            categorical_cols = X_train.select_dtypes(include=['object']).columns
            for col in categorical_cols:
                if col not in self.encoders:
                    self.encoders[col] = LabelEncoder()
                    X_train[col] = self.encoders[col].fit_transform(X_train[col].astype(str))
                else:
                    X_train[col] = self.encoders[col].transform(X_train[col].astype(str))
            
            # Save encoders
            joblib.dump(self.encoders, self.model_path / 'encoders.pkl')
            
            # Scale features
            self.scaler = StandardScaler()
            X_train = self.scaler.fit_transform(X_train)
            joblib.dump(self.scaler, self.model_path / 'scaler.pkl')
            
            # Encode labels
            self.label_encoder = LabelEncoder()
            y_train = self.label_encoder.fit_transform(y_train)
            joblib.dump(self.label_encoder, self.model_path / 'label_encoder.pkl')
            
            logger.info(f"✓ Data preprocessed: {X_train.shape}")
            
            # Process test set if provided
            if X_test is not None:
                y_test = X_test['label'] if 'label' in X_test.columns else X_test.iloc[:, -1]
                X_test = X_test.drop(['label'] if 'label' in X_test.columns else X_test.columns[-1], axis=1)
                
                for col in categorical_cols:
                    if col in X_test.columns:
                        X_test[col] = self.encoders[col].transform(X_test[col].astype(str))
                
                X_test = self.scaler.transform(X_test)
                y_test = self.label_encoder.transform(y_test)
                
                return X_train, y_train, X_test, y_test
            
            return X_train, y_train, None, None
        
        except Exception as e:
            logger.error(f"Preprocessing failed: {e}")
            return None, None, None, None
    
    def train_models(self, X_train, y_train, X_test=None, y_test=None):
        """Train all models"""
        try:
            logger.info("Training models...")
            
            results = {}
            
            # 1. Isolation Forest (Anomaly Detection)
            logger.info("Training Isolation Forest...")
            iso_forest = IsolationForest(contamination=0.1, random_state=42, n_jobs=-1)
            iso_forest.fit(X_train)
            joblib.dump(iso_forest, self.model_path / 'isolation_forest.pkl')
            
            if X_test is not None:
                iso_pred = iso_forest.predict(X_test)
                iso_accuracy = accuracy_score(y_test, (iso_pred + 1) // 2)  # Convert -1/1 to 0/1
                results['isolation_forest'] = {'accuracy': iso_accuracy}
                logger.info(f"✓ Isolation Forest Accuracy: {iso_accuracy:.4f}")
            
            # 2. Random Forest Binary (Normal vs Attack)
            logger.info("Training Random Forest Binary...")
            y_train_binary = (y_train > 0).astype(int)
            rf_binary = RandomForestClassifier(n_estimators=100, max_depth=20, random_state=42, n_jobs=-1)
            rf_binary.fit(X_train, y_train_binary)
            joblib.dump(rf_binary, self.model_path / 'rf_binary.pkl')
            
            if X_test is not None:
                y_test_binary = (y_test > 0).astype(int)
                binary_pred = rf_binary.predict(X_test)
                binary_accuracy = accuracy_score(y_test_binary, binary_pred)
                binary_precision = precision_score(y_test_binary, binary_pred, zero_division=0)
                binary_recall = recall_score(y_test_binary, binary_pred, zero_division=0)
                binary_f1 = f1_score(y_test_binary, binary_pred, zero_division=0)
                
                results['rf_binary'] = {
                    'accuracy': binary_accuracy,
                    'precision': binary_precision,
                    'recall': binary_recall,
                    'f1_score': binary_f1
                }
                logger.info(f"✓ RF Binary - Accuracy: {binary_accuracy:.4f}, F1: {binary_f1:.4f}")
            
            # 3. Random Forest Multi-class (Attack Type)
            logger.info("Training Random Forest Multi-class...")
            rf_multiclass = RandomForestClassifier(n_estimators=100, max_depth=20, random_state=42, n_jobs=-1)
            rf_multiclass.fit(X_train, y_train)
            joblib.dump(rf_multiclass, self.model_path / 'rf_multiclass.pkl')
            
            if X_test is not None:
                multiclass_pred = rf_multiclass.predict(X_test)
                multiclass_accuracy = accuracy_score(y_test, multiclass_pred)
                results['rf_multiclass'] = {'accuracy': multiclass_accuracy}
                logger.info(f"✓ RF Multi-class Accuracy: {multiclass_accuracy:.4f}")
            
            logger.info("✓ All models trained successfully!")
            
            # Save results
            with open(self.model_path / 'training_results.json', 'w') as f:
                json.dump(results, f, indent=2)
            
            return True
        
        except Exception as e:
            logger.error(f"Model training failed: {e}")
            return False

def train_models():
    """Main training function"""
    logger.info("=" * 60)
    logger.info("HoneyTrack ML Model Training")
    logger.info("=" * 60)
    
    trainer = ModelTrainer()
    
    # Load data
    X_train, X_test = trainer.load_data()
    if X_train is None:
        logger.error("Failed to load data")
        return False
    
    # Preprocess
    if X_test is not None:
        X_train, y_train, X_test, y_test = trainer.preprocess_data(X_train, X_test)
    else:
        X_train, y_train, _, _ = trainer.preprocess_data(X_train)
        X_test, y_test = None, None
    
    if X_train is None:
        logger.error("Failed to preprocess data")
        return False
    
    # Train
    success = trainer.train_models(X_train, y_train, X_test, y_test)
    
    logger.info("=" * 60)
    if success:
        logger.info("✓ Training complete!")
    else:
        logger.info("✗ Training failed!")
    logger.info("=" * 60)
    
    return success

if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    train_models()
```

### Why: Need actual ML training pipeline

---

## **BUG #8: main.py - Missing Event Processing**

### ❌ Current Code:
```python
# No code processes events from Event Queue!
```

### ✅ Fixed Code - Add This Function:
```python
def process_events():
    """Process events from queue and save to database"""
    logger.info("Event processor started")
    
    while True:
        try:
            event = event_queue.get(timeout=1)
            
            if event:
                # Determine attack type
                attack_type = event.get('type', 'unknown')
                source_ip = event.get('source_ip', 'unknown')
                
                # Create details
                details = str(event)
                
                # Log to database
                if db:
                    success = db.log_attack(source_ip, attack_type, details)
                    if success:
                        logger.info(f"✓ Attack logged: {attack_type} from {source_ip}")
                    else:
                        logger.warning(f"Failed to log attack: {attack_type}")
                
                # Check with VirusTotal
                if vt and source_ip != 'unknown':
                    try:
                        vt_result = vt.check_ip(source_ip)
                        if vt_result.get('malicious', 0) > 0:
                            logger.warning(f"⚠️  Malicious IP detected: {source_ip}")
                    except:
                        pass
        
        except Exception as e:
            logger.error(f"Event processing error: {e}")

# Add this in main() function after starting honeypots:
def main():
    """Main function"""
    global db, vt
    
    logger.info("=" * 60)
    logger.info("HoneyTrack - Service-Emulating Honeypot")
    logger.info("=" * 60)
    
    # Initialize database
    try:
        db = DatabaseManager(
            host=os.getenv('DB_HOST', 'localhost'),
            port=int(os.getenv('DB_PORT', 3306)),
            user=os.getenv('DB_USER', 'root'),
            password=os.getenv('DB_PASSWORD', ''),
            database=os.getenv('DB_NAME', 'honeypot_db')
        )
        if db.connect():
            logger.info("✓ Database connected")
        else:
            logger.warning("⚠ Database connection failed")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
    
    # Initialize VirusTotal
    try:
        vt_key = os.getenv('VIRUSTOTAL_API_KEY')
        if vt_key:
            vt = VirusTotalClient(vt_key)
            logger.info("✓ VirusTotal client initialized")
        else:
            logger.warning("⚠ VirusTotal API key not configured")
    except Exception as e:
        logger.error(f"VirusTotal initialization failed: {e}")
    
    # Start honeypots
    run_honeypots()
    
    # ✅ START EVENT PROCESSOR (NEW!)
    event_processor_thread = threading.Thread(target=process_events, daemon=True)
    event_processor_thread.start()
    logger.info("✓ Event processor started")
    
    # Start Flask
    port = int(os.getenv('FLASK_PORT', 5000))
    logger.info(f"Starting Flask on port {port}...")
    logger.info(f"Open browser: http://localhost:{port}")
    
    app.run(host='0.0.0.0', port=port, debug=False)
```

### Why: Need to process events and save them to database

---

## 🎯 **PRODUCTION IMPROVEMENTS**

### **1. Add Connection Pooling**
```python
# In database/db_manager.py
from mysql.connector import pooling

class DatabaseManager:
    def __init__(self, host, port, user, password, database, pool_size=5):
        self.pool = pooling.MySQLConnectionPool(
            pool_name="honeytrack_pool",
            pool_size=pool_size,
            pool_reset_session=True,
            host=host,
            port=port,
            user=user,
            password=password,
            database=database
        )
        self.connection = None
    
    def connect(self) -> bool:
        try:
            self.connection = self.pool.get_connection()
            logger.info("Database pool connected")
            return True
        except Exception as e:
            logger.error(f"Database connection failed: {e}")
            return False
```

### **2. Add Retry Logic**
```python
# In database/db_manager.py
def execute_with_retry(self, query: str, params: tuple = (), max_retries: int = 3) -> bool:
    """Execute query with retry logic"""
    for attempt in range(max_retries):
        try:
            if not self.connection:
                self.connect()
            
            cursor = self.connection.cursor()
            cursor.execute(query, params)
            self.connection.commit()
            cursor.close()
            return True
        
        except Exception as e:
            logger.warning(f"Query attempt {attempt + 1} failed: {e}")
            if attempt < max_retries - 1:
                self.connection = None
                time.sleep(1)
            else:
                logger.error(f"Query failed after {max_retries} attempts")
                return False
```

### **3. Add Rate Limiting for VirusTotal**
```python
# In virustotal/vt_client.py
from datetime import datetime, timedelta

class VirusTotalClient:
    def __init__(self, api_key: str, rate_limit: int = 4):
        self.api_key = api_key
        self.rate_limit = rate_limit  # requests per minute
        self.last_request_time = None
        self.request_count = 0
    
    def _check_rate_limit(self):
        """Check and enforce rate limiting"""
        now = datetime.now()
        
        if self.last_request_time is None:
            self.last_request_time = now
            self.request_count = 1
        else:
            elapsed = (now - self.last_request_time).total_seconds()
            
            if elapsed < 60:
                if self.request_count >= self.rate_limit:
                    sleep_time = 60 - elapsed
                    logger.info(f"Rate limit reached, sleeping for {sleep_time:.1f}s")
                    time.sleep(sleep_time)
                    self.last_request_time = datetime.now()
                    self.request_count = 1
                else:
                    self.request_count += 1
            else:
                self.last_request_time = now
                self.request_count = 1
```

### **4. Add Caching for IP Checks**
```python
# In virustotal/vt_client.py
from functools import lru_cache

class VirusTotalClient:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.cache = {}
        self.cache_ttl = 3600  # 1 hour
    
    def check_ip(self, ip: str) -> Dict[str, Any]:
        """Check IP with caching"""
        # Check cache
        if ip in self.cache:
            cached_time, cached_result = self.cache[ip]
            if datetime.now() - cached_time < timedelta(seconds=self.cache_ttl):
                logger.info(f"Cache hit for IP: {ip}")
                return cached_result
        
        # Make API request
        result = self._check_ip_api(ip)
        
        # Cache result
        self.cache[ip] = (datetime.now(), result)
        
        return result
```

### **5. Add Logging Rotation**
```python
# In main.py
from logging.handlers import RotatingFileHandler

# Replace logging setup with:
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler(
            'logs/honeytrack.log',
            maxBytes=10485760,  # 10MB
            backupCount=5
        ),
        logging.StreamHandler()
    ]
)
```

### **6. Add Health Check Endpoint**
```python
# In main.py
@app.route('/health')
def health_check():
    """Health check endpoint"""
    health = {
        'status': 'healthy',
        'database': 'unknown',
        'honeypots': 'unknown',
        'virustotal': 'unknown'
    }
    
    # Check database
    if db:
        try:
            db.fetch_one("SELECT 1")
            health['database'] = 'connected'
        except:
            health['database'] = 'disconnected'
    
    # Check honeypots
    if ssh_honeypot.running and http_honeypot.running:
        health['honeypots'] = 'running'
    else:
        health['honeypots'] = 'stopped'
    
    # Check VirusTotal
    if vt:
        health['virustotal'] = 'configured'
    else:
        health['virustotal'] = 'not_configured'
    
    overall_status = 'healthy' if health['database'] == 'connected' else 'degraded'
    
    return jsonify({
        'status': overall_status,
        'components': health
    })
```

### **7. Add MITRE Integration to main.py**
```python
# In main.py
from mitre.mitre_mapper import mapper

# Add to process_events():
if event:
    # ... existing code ...
    
    # Map to MITRE ATT&CK
    if event.get('type') == 'ssh_connection':
        mitre_mapping = mapper.map_ssh_attack({
            'source_ip': source_ip,
            'failed_attempts': event.get('failed_attempts', 0)
        })
    elif event.get('type') == 'http_request':
        mitre_mapping = mapper.map_http_attack({
            'source_ip': source_ip,
            'method': event.get('method'),
            'path': event.get('path'),
            'payload': event.get('payload')
        })
    
    logger.info(f"MITRE Mapping: {mitre_mapping}")
```

---

## ✅ **SUMMARY OF FIXES**

| Bug | Severity | Status |
|-----|----------|--------|
| Hardcoded credentials in setup_db.py | 🔴 CRITICAL | FIX PROVIDED |
| No connection check in db_manager.py | 🔴 CRITICAL | FIX PROVIDED |
| Unsafe shutdown in main.py | 🟠 HIGH | FIX PROVIDED |
| Wrong MITRE mapping | 🟠 HIGH | FIX PROVIDED |
| VirusTotal stub | 🔴 CRITICAL | FIX PROVIDED |
| ML Predictor stub | 🔴 CRITICAL | FIX PROVIDED |
| ML Training stub | 🔴 CRITICAL | FIX PROVIDED |
| Missing event processing | 🔴 CRITICAL | FIX PROVIDED |

---

## 🚀 **NEXT STEPS**

1. ✅ Apply all bug fixes
2. ✅ Test each component
3. ✅ Add UNSW-NB15 data files
4. ✅ Run training: `python ml/honeytrack_ml.py`
5. ✅ Validate config: `python validate_env.py`
6. ✅ Setup database: `python setup_db.py`
7. ✅ Run system: `python main.py`

