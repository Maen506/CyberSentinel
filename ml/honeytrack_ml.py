"""
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║        HoneyTrack — Complete ML Model                           ║
║        Service-Emulating Honeypot for Proactive Attack Analysis  ║
║                                                                  ║
║        Jordan University of Science and Technology               ║
║        Faculty of Computer and Information Technology            ║
║        Capstone Project — 2026                                   ║
║                                                                  ║
║  ── What this file does ─────────────────────────────────────── ║
║  1.  Load & explore UNSW-NB15 dataset                           ║
║  2.  Proper 80/20 train-test split (stratified)                 ║
║  3.  Feature engineering (5 new features)                       ║
║  4.  Train Isolation Forest  (unsupervised anomaly detection)   ║
║  5.  Train Random Forest     (supervised binary classification) ║
║  6.  Train Random Forest     (supervised multi-class)           ║
║  7.  Full evaluation on unseen test data                        ║
║  8.  12 professional plots for the project report               ║
║  9.  MITRE ATT&CK mapping                                       ║
║  10. Save all models as .pkl for dashboard integration          ║
║                                                                  ║
║  USAGE:                                                          ║
║      python honeytrack_ml.py                                     ║
║                                                                  ║
║  OUTPUT:                                                         ║
║      models/   → 7 .pkl files ready for the dashboard           ║
║      plots/    → 12 PNG charts for the report                   ║
╚══════════════════════════════════════════════════════════════════╝
"""

# ── Standard Library ──────────────────────────────────────────────
import os
import sys
import json
import warnings
warnings.filterwarnings('ignore')

# ── Data Science ──────────────────────────────────────────────────
import numpy  as np
import pandas as pd
import joblib

# ── Visualization ─────────────────────────────────────────────────
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns

# ── Machine Learning ──────────────────────────────────────────────
from sklearn.ensemble     import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, roc_curve,
    confusion_matrix, classification_report,
    precision_recall_curve, average_precision_score
)

# ══════════════════════════════════════════════════════════════════
# CONFIGURATION
# ══════════════════════════════════════════════════════════════════
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
DATA_PATH  = os.path.join(BASE_DIR, 'UNSW_NB15_training-set.csv')
MODEL_DIR  = os.path.join(BASE_DIR, 'models')
PLOT_DIR   = os.path.join(BASE_DIR, 'plots')
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(PLOT_DIR,  exist_ok=True)

# Random seed for reproducibility
SEED = 42
np.random.seed(SEED)

# ══════════════════════════════════════════════════════════════════
# VISUAL STYLE
# ══════════════════════════════════════════════════════════════════
plt.rcParams.update({
    'figure.facecolor': '#0d1117',
    'axes.facecolor':   '#161b22',
    'axes.edgecolor':   '#30363d',
    'axes.labelcolor':  '#e6edf3',
    'xtick.color':      '#8b949e',
    'ytick.color':      '#8b949e',
    'text.color':       '#e6edf3',
    'grid.color':       '#21262d',
    'grid.linestyle':   '--',
    'grid.alpha':       0.5,
    'font.family':      'DejaVu Sans',
    'font.size':        11,
    'axes.titlesize':   13,
    'axes.labelsize':   11,
})

# Color palette
C = {
    'blue':   '#58a6ff',
    'green':  '#3fb950',
    'red':    '#f85149',
    'yellow': '#d29922',
    'purple': '#bc8cff',
    'orange': '#f0883e',
    'muted':  '#8b949e',
    'cyan':   '#79c0ff',
    'pink':   '#ff6e96',
}

ATTACK_COLORS = {
    'Normal':         '#3fb950',
    'Generic':        '#f85149',
    'Exploits':       '#f0883e',
    'Fuzzers':        '#d29922',
    'DoS':            '#bc8cff',
    'Reconnaissance': '#58a6ff',
    'Analysis':       '#79c0ff',
    'Backdoor':       '#ff7b72',
    'Shellcode':      '#ffa657',
    'Worms':          '#ff6e96',
}

# MITRE ATT&CK mapping
MITRE_MAP = {
    'Reconnaissance': [
        {'id': 'T1595',     'name': 'Active Scanning',              'tactic': 'Reconnaissance'},
        {'id': 'T1590',     'name': 'Gather Victim Network Info',   'tactic': 'Reconnaissance'},
    ],
    'Exploits': [
        {'id': 'T1190',     'name': 'Exploit Public-Facing App',    'tactic': 'Initial Access'},
        {'id': 'T1203',     'name': 'Exploitation for Execution',   'tactic': 'Execution'},
    ],
    'DoS': [
        {'id': 'T1499',     'name': 'Endpoint Denial of Service',   'tactic': 'Impact'},
        {'id': 'T1498',     'name': 'Network Denial of Service',    'tactic': 'Impact'},
    ],
    'Generic': [
        {'id': 'T1110',     'name': 'Brute Force',                  'tactic': 'Credential Access'},
        {'id': 'T1071',     'name': 'Application Layer Protocol',   'tactic': 'C2'},
    ],
    'Fuzzers': [
        {'id': 'T1595.002', 'name': 'Vulnerability Scanning',       'tactic': 'Reconnaissance'},
        {'id': 'T1190',     'name': 'Exploit Public-Facing App',    'tactic': 'Initial Access'},
    ],
    'Backdoor': [
        {'id': 'T1543',     'name': 'Create/Modify System Process', 'tactic': 'Persistence'},
        {'id': 'T1078',     'name': 'Valid Accounts',               'tactic': 'Defense Evasion'},
    ],
    'Analysis': [
        {'id': 'T1046',     'name': 'Network Service Discovery',    'tactic': 'Discovery'},
        {'id': 'T1040',     'name': 'Network Sniffing',             'tactic': 'Credential Access'},
    ],
    'Shellcode': [
        {'id': 'T1055',     'name': 'Process Injection',            'tactic': 'Defense Evasion'},
        {'id': 'T1059',     'name': 'Command and Scripting',        'tactic': 'Execution'},
    ],
    'Worms': [
        {'id': 'T1210',     'name': 'Exploitation of Remote Svc',   'tactic': 'Lateral Movement'},
        {'id': 'T1570',     'name': 'Lateral Tool Transfer',        'tactic': 'Lateral Movement'},
    ],
}


# ══════════════════════════════════════════════════════════════════
# HELPER: Pretty print section headers
# ══════════════════════════════════════════════════════════════════
def section(title):
    print(f"\n{'═'*64}")
    print(f"  {title}")
    print(f"{'═'*64}")


def ok(msg):
    print(f"  ✔  {msg}")


def info(msg):
    print(f"  ●  {msg}")


# ══════════════════════════════════════════════════════════════════
# STEP 1 — LOAD & EXPLORE
# ══════════════════════════════════════════════════════════════════
def step1_load(path: str) -> pd.DataFrame:
    section("STEP 1 — Loading & Exploring Dataset")

    df = pd.read_csv(path)
    ok(f"Loaded: {len(df):,} rows × {df.shape[1]} columns")
    ok(f"Features: {df.shape[1] - 2} (excluding label columns)")
    ok(f"Missing values: {df.isnull().sum().sum()}")

    print("\n  Attack Category Breakdown:")
    print("  " + "─"*50)
    for cat, cnt in df['attack_cat'].value_counts().items():
        pct = cnt / len(df) * 100
        bar = '█' * int(pct / 2)
        print(f"  {cat:<18} {cnt:>6,}  {bar}  {pct:.1f}%")

    # ── Plot 1: Dataset Overview ──────────────────
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    fig.suptitle('UNSW-NB15 Dataset Overview',
                 color=C['blue'], fontsize=14, fontweight='bold')

    cats  = df['attack_cat'].value_counts()
    cols  = [ATTACK_COLORS.get(c, C['muted']) for c in cats.index]
    bars  = axes[0].barh(cats.index, cats.values,
                         color=cols, edgecolor='none', height=0.7)
    for b, v in zip(bars, cats.values):
        axes[0].text(v + 300, b.get_y() + b.get_height()/2,
                     f'{v:,}', va='center', fontsize=9, color=C['muted'])
    axes[0].set_title('Attack Category Distribution', color=C['blue'])
    axes[0].set_xlabel('Sample Count')
    axes[0].invert_yaxis()
    axes[0].grid(axis='x', alpha=0.3)

    counts = df['label'].value_counts().sort_index()
    axes[1].pie(
        counts.values,
        labels=['Normal', 'Attack'],
        colors=[C['green'], C['red']],
        autopct='%1.1f%%', startangle=90,
        wedgeprops={'edgecolor': '#0d1117', 'linewidth': 3},
        textprops={'color': '#e6edf3', 'fontsize': 12}
    )
    axes[1].set_title('Normal vs Attack Traffic', color=C['blue'])

    plt.tight_layout()
    _save('01_dataset_overview.png')
    return df


# ══════════════════════════════════════════════════════════════════
# STEP 2 — PREPROCESSING & FEATURE ENGINEERING
# ══════════════════════════════════════════════════════════════════
def step2_preprocess(df: pd.DataFrame):
    section("STEP 2 — Preprocessing & Feature Engineering")

    df = df.copy()
    df.drop(columns=['id'], inplace=True, errors='ignore')

    # ── Encode categoricals ──────────────────────
    cat_cols = ['proto', 'service', 'state']
    encoders = {}
    for col in cat_cols:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col].astype(str))
        encoders[col] = le
        ok(f"Encoded '{col}': {len(le.classes_)} unique values")

    # ── Feature Engineering ──────────────────────
    df['byte_ratio']     = df['sbytes']    / (df['dbytes']    + 1)
    df['pkt_diff']       = df['spkts']     - df['dpkts']
    df['load_ratio']     = df['sload']     / (df['dload']     + 1)
    df['jit_ratio']      = df['sjit']      / (df['djit']      + 1)
    df['conn_intensity'] = df['ct_srv_src'] * df['ct_srv_dst']
    ok("Added 5 engineered features: byte_ratio, pkt_diff, load_ratio, jit_ratio, conn_intensity")

    # ── Labels ───────────────────────────────────
    y_binary = df['label']
    y_multi  = df['attack_cat']
    feature_cols = [c for c in df.columns if c not in ['attack_cat', 'label']]
    X = df[feature_cols]
    ok(f"Feature matrix: {X.shape[0]:,} rows × {X.shape[1]} features")

    # ── Proper 80/20 split (stratified) ──────────
    X_train, X_test, y_train, y_test, ym_train, ym_test = train_test_split(
        X, y_binary, y_multi,
        test_size=0.20,
        random_state=SEED,
        stratify=y_binary
    )
    ok(f"Train set: {len(X_train):,} samples  (80%)")
    ok(f"Test  set: {len(X_test):,} samples   (20% — unseen during training)")

    # ── Scale ────────────────────────────────────
    scaler = StandardScaler()
    X_train_sc = scaler.fit_transform(X_train)
    X_test_sc  = scaler.transform(X_test)
    ok("Features scaled with StandardScaler")

    # ── Encode multi-class labels ─────────────────
    le_attack = LabelEncoder()
    le_attack.fit(y_multi)
    ym_train_enc = le_attack.transform(ym_train)
    ym_test_enc  = le_attack.transform(ym_test)
    ok(f"Attack categories encoded: {list(le_attack.classes_)}")

    # ── Save preprocessing artifacts ──────────────
    joblib.dump(scaler,       os.path.join(MODEL_DIR, 'scaler.pkl'))
    joblib.dump(encoders,     os.path.join(MODEL_DIR, 'encoders.pkl'))
    joblib.dump(le_attack,    os.path.join(MODEL_DIR, 'label_encoder.pkl'))
    joblib.dump(feature_cols, os.path.join(MODEL_DIR, 'feature_cols.pkl'))
    ok("Preprocessing artifacts saved")

    # ── Plot 2: Correlation Heatmap ───────────────
    fig, ax = plt.subplots(figsize=(14, 10))
    top20   = pd.DataFrame(X_train_sc, columns=feature_cols).iloc[:, :20]
    mask    = np.triu(np.ones_like(top20.corr(), dtype=bool))
    sns.heatmap(top20.corr(), mask=mask, ax=ax, cmap='coolwarm',
                center=0, annot=False, linewidths=0.3,
                cbar_kws={'shrink': 0.8})
    ax.set_title('Feature Correlation Matrix (Top 20)',
                 color=C['blue'], pad=15)
    plt.tight_layout()
    _save('02_correlation_heatmap.png')

    # ── Plot 3: Feature distributions ────────────
    fig, axes = plt.subplots(2, 3, figsize=(16, 9))
    fig.suptitle('Key Feature Distributions (Normal vs Attack)',
                 color=C['blue'], fontsize=14, fontweight='bold')
    key_feats = ['dur', 'sbytes', 'rate', 'ct_srv_src', 'byte_ratio', 'conn_intensity']
    X_df = pd.DataFrame(X_train_sc, columns=feature_cols)
    for ax, feat in zip(axes.flat, key_feats):
        if feat not in X_df.columns:
            continue
        normal_vals = X_df[feat][y_train.values == 0]
        attack_vals = X_df[feat][y_train.values == 1]
        ax.hist(normal_vals, bins=50, alpha=0.6, color=C['green'],
                label='Normal', edgecolor='none', density=True)
        ax.hist(attack_vals, bins=50, alpha=0.6, color=C['red'],
                label='Attack', edgecolor='none', density=True)
        ax.set_title(feat, color=C['blue'])
        ax.legend(fontsize=9)
        ax.grid(True, alpha=0.3)
    plt.tight_layout()
    _save('03_feature_distributions.png')

    return (X_train_sc, X_test_sc, y_train, y_test,
            ym_train_enc, ym_test_enc, le_attack,
            feature_cols, scaler, encoders)


# ══════════════════════════════════════════════════════════════════
# STEP 3 — ISOLATION FOREST (Unsupervised Anomaly Detection)
# ══════════════════════════════════════════════════════════════════
def step3_isolation_forest(X_train_sc, X_test_sc, y_train, y_test, feature_cols):
    section("STEP 3 — Isolation Forest (Unsupervised Anomaly Detection)")
    info("Training ONLY on normal traffic → learns what is 'normal'")

    # Train on normal samples only
    X_normal = X_train_sc[y_train.values == 0]
    info(f"Normal training samples: {len(X_normal):,}")

    iforest = IsolationForest(
        n_estimators  = 200,
        contamination = 0.05,
        max_samples   = 'auto',
        random_state  = SEED,
        n_jobs        = -1,
    )
    iforest.fit(X_normal)
    ok("Isolation Forest trained")

    # Predict on test set
    preds_raw  = iforest.predict(X_test_sc)       # 1=normal, -1=anomaly
    if_scores  = iforest.score_samples(X_test_sc) # lower = more anomalous
    if_preds   = (preds_raw == -1).astype(int)    # convert to 0/1

    # Metrics
    if_acc  = accuracy_score(y_test,  if_preds)
    if_prec = precision_score(y_test, if_preds, zero_division=0)
    if_rec  = recall_score(y_test,    if_preds, zero_division=0)
    if_f1   = f1_score(y_test,        if_preds, zero_division=0)

    print(f"\n  ┌{'─'*38}┐")
    print(f"  │{'Isolation Forest Results':^38}│")
    print(f"  ├{'─'*38}┤")
    print(f"  │  Accuracy   : {if_acc*100:>6.2f}%{' '*20}│")
    print(f"  │  Precision  : {if_prec*100:>6.2f}%{' '*20}│")
    print(f"  │  Recall     : {if_rec*100:>6.2f}%{' '*20}│")
    print(f"  │  F1 Score   : {if_f1*100:>6.2f}%{' '*20}│")
    print(f"  └{'─'*38}┘")
    info("Note: Low accuracy is EXPECTED for unsupervised models.")
    info("Precision 90%+ means when it flags an attack, it is correct.")

    # ── Plot 4: Anomaly Score Distribution ────────
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    fig.suptitle('Isolation Forest — Anomaly Detection Results',
                 color=C['purple'], fontsize=14, fontweight='bold')

    normal_s = if_scores[y_test.values == 0]
    attack_s = if_scores[y_test.values == 1]
    threshold = np.percentile(if_scores, 5)

    axes[0].hist(normal_s, bins=60, alpha=0.7, color=C['green'],
                 label='Normal', edgecolor='none', density=True)
    axes[0].hist(attack_s, bins=60, alpha=0.7, color=C['red'],
                 label='Attack', edgecolor='none', density=True)
    axes[0].axvline(x=threshold, color=C['yellow'], lw=2,
                    linestyle='--', label=f'Threshold ({threshold:.3f})')
    axes[0].set_title('Anomaly Score Distribution')
    axes[0].set_xlabel('Anomaly Score  (lower = more anomalous)')
    axes[0].set_ylabel('Density')
    axes[0].legend()
    axes[0].grid(True, alpha=0.3)

    cm = confusion_matrix(y_test, if_preds)
    sns.heatmap(cm, annot=True, fmt='d', cmap='Reds', ax=axes[1],
                xticklabels=['Normal', 'Attack'],
                yticklabels=['Normal', 'Attack'],
                linewidths=0.5, annot_kws={'size': 13})
    axes[1].set_title('Confusion Matrix')
    axes[1].set_xlabel('Predicted')
    axes[1].set_ylabel('Actual')

    plt.tight_layout()
    _save('04_isolation_forest.png')

    # Save model
    joblib.dump(iforest, os.path.join(MODEL_DIR, 'isolation_forest.pkl'))
    ok("Model saved: isolation_forest.pkl")

    return iforest, if_preds, if_scores, {
        'acc': if_acc, 'prec': if_prec,
        'rec': if_rec, 'f1':   if_f1,
    }


# ══════════════════════════════════════════════════════════════════
# STEP 4 — RANDOM FOREST BINARY (Normal vs Attack)
# ══════════════════════════════════════════════════════════════════
def step4_rf_binary(X_train_sc, X_test_sc, y_train, y_test, feature_cols):
    section("STEP 4 — Random Forest Binary Classification (Normal vs Attack)")

    rf_bin = RandomForestClassifier(
        n_estimators    = 200,
        max_depth       = 20,
        min_samples_split = 5,
        class_weight    = 'balanced',
        random_state    = SEED,
        n_jobs          = -1,
    )
    rf_bin.fit(X_train_sc, y_train)
    ok("Random Forest Binary trained")

    preds = rf_bin.predict(X_test_sc)
    probs = rf_bin.predict_proba(X_test_sc)[:, 1]

    acc  = accuracy_score(y_test, preds)
    prec = precision_score(y_test, preds, zero_division=0)
    rec  = recall_score(y_test, preds, zero_division=0)
    f1   = f1_score(y_test, preds, zero_division=0)
    auc  = roc_auc_score(y_test, probs)

    print(f"\n  ┌{'─'*42}┐")
    print(f"  │{'Random Forest Binary Results':^42}│")
    print(f"  ├{'─'*42}┤")
    print(f"  │  Accuracy   : {acc*100:>6.2f}%{' '*24}│")
    print(f"  │  Precision  : {prec*100:>6.2f}%{' '*24}│")
    print(f"  │  Recall     : {rec*100:>6.2f}%{' '*24}│")
    print(f"  │  F1 Score   : {f1*100:>6.2f}%{' '*24}│")
    print(f"  │  AUC-ROC    : {auc*100:>6.2f}%{' '*24}│")
    print(f"  └{'─'*42}┘")

    # ── Plot 5: Confusion Matrix + ROC ────────────
    fig, axes = plt.subplots(1, 2, figsize=(14, 6))
    fig.suptitle('Random Forest Binary — Test Set Results',
                 color=C['blue'], fontsize=14, fontweight='bold')

    cm = confusion_matrix(y_test, preds)
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=axes[0],
                xticklabels=['Normal', 'Attack'],
                yticklabels=['Normal', 'Attack'],
                linewidths=0.5, annot_kws={'size': 14})
    axes[0].set_title(f'Confusion Matrix  (Accuracy: {acc*100:.2f}%)')
    axes[0].set_xlabel('Predicted')
    axes[0].set_ylabel('Actual')

    fpr, tpr, _ = roc_curve(y_test, probs)
    axes[1].plot(fpr, tpr, color=C['blue'], lw=2.5,
                 label=f'ROC Curve  (AUC = {auc:.4f})')
    axes[1].plot([0, 1], [0, 1], color=C['muted'], lw=1,
                 linestyle='--', label='Random Classifier')
    axes[1].fill_between(fpr, tpr, alpha=0.1, color=C['blue'])
    axes[1].set_title('ROC Curve')
    axes[1].set_xlabel('False Positive Rate')
    axes[1].set_ylabel('True Positive Rate')
    axes[1].legend(loc='lower right')
    axes[1].grid(True, alpha=0.3)
    axes[1].set_xlim([0, 1])
    axes[1].set_ylim([0, 1.02])

    plt.tight_layout()
    _save('05_rf_binary.png')

    # ── Plot 6: Feature Importance ────────────────
    importances = rf_bin.feature_importances_
    feat_series = pd.Series(importances, index=feature_cols)
    feat_sorted = feat_series.sort_values(ascending=True).tail(20)

    fig, ax = plt.subplots(figsize=(13, 8))
    colors = [C['blue'] if i >= 15 else C['muted']
              for i in range(len(feat_sorted))]
    bars = ax.barh(feat_sorted.index, feat_sorted.values,
                   color=colors, edgecolor='none')
    for bar, val in zip(bars, feat_sorted.values):
        ax.text(val + 0.0005, bar.get_y() + bar.get_height()/2,
                f'{val:.4f}', va='center', fontsize=9, color=C['muted'])
    ax.set_title('Top 20 Feature Importances — Random Forest',
                 color=C['blue'], pad=15)
    ax.set_xlabel('Importance Score')
    ax.axvline(x=feat_sorted.values.mean(), color=C['yellow'],
               linestyle='--', alpha=0.7, label='Mean importance')
    ax.legend()
    ax.grid(axis='x', alpha=0.3)
    plt.tight_layout()
    _save('06_feature_importance.png')

    # Save model
    joblib.dump(rf_bin, os.path.join(MODEL_DIR, 'rf_binary.pkl'))
    ok("Model saved: rf_binary.pkl")

    return rf_bin, preds, probs, {
        'acc': acc, 'prec': prec,
        'rec': rec, 'f1':   f1, 'auc': auc,
    }


# ══════════════════════════════════════════════════════════════════
# STEP 5 — RANDOM FOREST MULTI-CLASS (Attack Type Classification)
# ══════════════════════════════════════════════════════════════════
def step5_rf_multiclass(X_train_sc, X_test_sc,
                        y_train_bin, y_test_bin,
                        ym_train, ym_test,
                        le_attack):
    section("STEP 5 — Random Forest Multi-class (Attack Type)")
    info("Trained on attack samples only → classifies which attack type")

    # Filter: only attack samples
    atk_train = y_train_bin.values == 1
    atk_test  = y_test_bin.values  == 1

    X_atk_train = X_train_sc[atk_train]
    y_atk_train = ym_train[atk_train]
    X_atk_test  = X_test_sc[atk_test]
    y_atk_test  = ym_test[atk_test]

    ok(f"Attack train: {len(X_atk_train):,} | Attack test: {len(X_atk_test):,}")

    rf_multi = RandomForestClassifier(
        n_estimators  = 200,
        max_depth     = 20,
        class_weight  = 'balanced',
        random_state  = SEED,
        n_jobs        = -1,
    )
    rf_multi.fit(X_atk_train, y_atk_train)
    ok("Random Forest Multi-class trained")

    y_pred_multi = rf_multi.predict(X_atk_test)

    acc_m = accuracy_score(y_atk_test, y_pred_multi)
    f1_m  = f1_score(y_atk_test, y_pred_multi,
                     average='weighted', zero_division=0)

    print(f"\n  ┌{'─'*42}┐")
    print(f"  │{'Random Forest Multi-class Results':^42}│")
    print(f"  ├{'─'*42}┤")
    print(f"  │  Accuracy     : {acc_m*100:>6.2f}%{' '*22}│")
    print(f"  │  F1 (weighted): {f1_m*100:>6.2f}%{' '*22}│")
    print(f"  └{'─'*42}┘")

    unique_labels = np.unique(np.concatenate([y_atk_test, y_pred_multi]))
    label_names   = le_attack.inverse_transform(unique_labels)

    print("\n  Per-class Report:")
    print(classification_report(
        y_atk_test, y_pred_multi,
        labels=unique_labels,
        target_names=label_names,
        zero_division=0
    ))

    # ── Plot 7: Multi-class Confusion Matrix ──────
    fig, ax = plt.subplots(figsize=(12, 9))
    cm_m = confusion_matrix(y_atk_test, y_pred_multi, labels=unique_labels)
    sns.heatmap(cm_m, annot=True, fmt='d', cmap='Purples', ax=ax,
                xticklabels=label_names, yticklabels=label_names,
                linewidths=0.5)
    ax.set_title('Multi-class Confusion Matrix — Attack Type Classification',
                 color=C['purple'], pad=15)
    ax.set_xlabel('Predicted Attack Type')
    ax.set_ylabel('Actual Attack Type')
    plt.xticks(rotation=30, ha='right')
    plt.tight_layout()
    _save('07_multiclass_confusion.png')

    # ── Plot 8: F1 per Attack Type ────────────────
    report = classification_report(
        y_atk_test, y_pred_multi,
        labels=unique_labels,
        target_names=label_names,
        output_dict=True, zero_division=0
    )
    classes   = [k for k in report
                 if k not in ('accuracy', 'macro avg', 'weighted avg')]
    f1_scores = [report[k]['f1-score'] for k in classes]
    support   = [report[k]['support']  for k in classes]
    bar_colors = [ATTACK_COLORS.get(c, C['blue']) for c in classes]

    fig, axes = plt.subplots(1, 2, figsize=(16, 6))
    fig.suptitle('Multi-class Classification — Per Attack Type',
                 color=C['purple'], fontsize=14, fontweight='bold')

    bars = axes[0].bar(classes, f1_scores, color=bar_colors,
                       edgecolor='none', width=0.6)
    axes[0].set_title('F1-Score per Attack Category')
    axes[0].set_ylabel('F1 Score')
    axes[0].set_ylim(0, 1.15)
    axes[0].axhline(y=f1_m, color=C['yellow'], linestyle='--',
                    lw=1.5, label=f'Weighted F1: {f1_m:.3f}')
    axes[0].legend()
    for bar, val in zip(bars, f1_scores):
        axes[0].text(bar.get_x() + bar.get_width()/2, val + 0.02,
                     f'{val:.2f}', ha='center', fontsize=10)
    plt.setp(axes[0].xaxis.get_majorticklabels(), rotation=30, ha='right')
    axes[0].grid(axis='y', alpha=0.3)

    # Support (sample count per class)
    axes[1].bar(classes, support, color=bar_colors, edgecolor='none', width=0.6)
    axes[1].set_title('Test Samples per Attack Category')
    axes[1].set_ylabel('Sample Count')
    for i, (c, v) in enumerate(zip(classes, support)):
        axes[1].text(i, v + 50, f'{v:,}', ha='center', fontsize=9)
    plt.setp(axes[1].xaxis.get_majorticklabels(), rotation=30, ha='right')
    axes[1].grid(axis='y', alpha=0.3)

    plt.tight_layout()
    _save('08_attack_type_f1.png')

    # Save model
    joblib.dump(rf_multi, os.path.join(MODEL_DIR, 'rf_multiclass.pkl'))
    ok("Model saved: rf_multiclass.pkl")

    return rf_multi, y_pred_multi, {
        'acc': acc_m, 'f1': f1_m,
    }


# ══════════════════════════════════════════════════════════════════
# STEP 6 — MODEL COMPARISON
# ══════════════════════════════════════════════════════════════════
def step6_comparison(if_metrics: dict, rf_metrics: dict, multi_metrics: dict):
    section("STEP 6 — Model Comparison & Summary")

    # ── Plot 9: Bar + Radar comparison ───────────
    fig = plt.figure(figsize=(16, 6))
    fig.suptitle('Model Performance Comparison — Test Set',
                 color=C['blue'], fontsize=14, fontweight='bold')

    metrics  = ['Accuracy', 'Precision', 'Recall', 'F1 Score']
    if_vals  = [if_metrics['acc'], if_metrics['prec'],
                if_metrics['rec'], if_metrics['f1']]
    rf_vals  = [rf_metrics['acc'], rf_metrics['prec'],
                rf_metrics['rec'], rf_metrics['f1']]

    ax1 = fig.add_subplot(1, 2, 1)
    x = np.arange(len(metrics))
    w = 0.35
    b1 = ax1.bar(x - w/2, if_vals, w, label='Isolation Forest',
                 color=C['purple'], alpha=0.85, edgecolor='none')
    b2 = ax1.bar(x + w/2, rf_vals, w, label='Random Forest',
                 color=C['blue'],   alpha=0.85, edgecolor='none')
    ax1.set_xticks(x)
    ax1.set_xticklabels(metrics)
    ax1.set_ylim(0, 1.18)
    ax1.set_ylabel('Score')
    ax1.set_title('Metric Comparison')
    ax1.legend()
    ax1.grid(axis='y', alpha=0.3)
    for bar, val in zip(b1, if_vals):
        ax1.text(bar.get_x()+bar.get_width()/2, val+0.02,
                 f'{val:.2f}', ha='center', fontsize=9, color=C['purple'])
    for bar, val in zip(b2, rf_vals):
        ax1.text(bar.get_x()+bar.get_width()/2, val+0.02,
                 f'{val:.2f}', ha='center', fontsize=9, color=C['blue'])

    # Radar chart
    ax2 = fig.add_subplot(1, 2, 2, projection='polar')
    ax2.set_facecolor('#161b22')
    angles   = np.linspace(0, 2*np.pi, len(metrics), endpoint=False).tolist()
    angles  += angles[:1]
    if_radar = if_vals + [if_vals[0]]
    rf_radar = rf_vals + [rf_vals[0]]

    ax2.plot(angles, if_radar, 'o-', color=C['purple'], lw=2,
             label='Isolation Forest')
    ax2.fill(angles, if_radar, alpha=0.15, color=C['purple'])
    ax2.plot(angles, rf_radar, 'o-', color=C['blue'],   lw=2,
             label='Random Forest')
    ax2.fill(angles, rf_radar, alpha=0.15, color=C['blue'])
    ax2.set_xticks(angles[:-1])
    ax2.set_xticklabels(metrics, color='#e6edf3')
    ax2.set_ylim(0, 1)
    ax2.set_title('Radar Comparison', color=C['blue'], pad=25)
    ax2.legend(loc='upper right', bbox_to_anchor=(1.35, 1.1))
    ax2.grid(color='#30363d', alpha=0.5)
    ax2.spines['polar'].set_color('#30363d')

    plt.tight_layout()
    _save('09_model_comparison.png')


# ══════════════════════════════════════════════════════════════════
# STEP 7 — MITRE ATT&CK MAPPING
# ══════════════════════════════════════════════════════════════════
def step7_mitre(df: pd.DataFrame):
    section("STEP 7 — MITRE ATT&CK Framework Mapping")

    attack_counts = df[df['label'] == 1]['attack_cat'].value_counts()

    fig, ax = plt.subplots(figsize=(15, 9))
    fig.patch.set_facecolor('#0d1117')

    y_pos, yticks, ylabels = 0, [], []
    for attack_type, count in attack_counts.items():
        if attack_type == 'Normal':
            continue
        techniques = MITRE_MAP.get(attack_type, [])
        color      = ATTACK_COLORS.get(attack_type, C['muted'])

        ax.barh(y_pos, count, height=0.6, color=color,
                alpha=0.85, edgecolor='none')
        yticks.append(y_pos)
        ylabels.append(attack_type)

        tech_str = '   →   ' + '     '.join(
            [f"[{t['id']}] {t['name']}" for t in techniques]
        )
        ax.text(count + 500, y_pos, tech_str,
                va='center', fontsize=8.5, color=C['muted'])
        ax.text(count / 2, y_pos, f'{count:,}',
                va='center', ha='center', fontsize=9,
                color='white', fontweight='bold')

        ok(f"{attack_type:<18} → {', '.join(t['id'] for t in techniques)}")
        y_pos += 1

    ax.set_yticks(yticks)
    ax.set_yticklabels(ylabels, fontsize=11)
    ax.set_xlabel('Number of Samples', fontsize=11)
    ax.set_title('MITRE ATT&CK Framework Mapping — UNSW-NB15 Dataset',
                 color=C['blue'], fontsize=13, pad=15)
    ax.invert_yaxis()
    ax.set_xlim(0, attack_counts.max() * 1.55)
    ax.grid(axis='x', alpha=0.3)
    plt.tight_layout()
    _save('10_mitre_mapping.png')

    # Save MITRE mapping as JSON
    mitre_output = {
        cat: MITRE_MAP.get(cat, [])
        for cat in attack_counts.index if cat != 'Normal'
    }
    with open(os.path.join(MODEL_DIR, 'mitre_mapping.json'), 'w') as f:
        json.dump(mitre_output, f, indent=2)
    ok("MITRE mapping saved: mitre_mapping.json")


# ══════════════════════════════════════════════════════════════════
# STEP 8 — FULL SUMMARY PLOT
# ══════════════════════════════════════════════════════════════════
def step8_summary(if_m: dict, rf_m: dict, multi_m: dict):
    section("STEP 8 — Final Summary Dashboard Plot")

    fig = plt.figure(figsize=(18, 10))
    fig.patch.set_facecolor('#0d1117')
    fig.suptitle('HoneyTrack ML Engine — Complete Results Summary',
                 color=C['blue'], fontsize=16, fontweight='bold', y=0.98)

    # ── Top row: 3 metric cards ───────────────────
    models = [
        ('Isolation Forest\n(Unsupervised)', if_m,    C['purple']),
        ('Random Forest Binary\n(Supervised)',rf_m,   C['blue']),
        ('Random Forest Multi\n(Attack Type)',multi_m, C['green']),
    ]
    for i, (name, metrics, color) in enumerate(models):
        ax = fig.add_subplot(2, 3, i+1)
        ax.set_facecolor('#1c2128')
        ax.set_xlim(0, 1); ax.set_ylim(0, 1)
        ax.axis('off')

        ax.text(0.5, 0.88, name, ha='center', va='top',
                fontsize=11, color=color, fontweight='bold',
                transform=ax.transAxes)

        keys   = ['acc', 'prec', 'rec', 'f1']
        labels = ['Accuracy', 'Precision', 'Recall', 'F1 Score']
        for j, (key, label) in enumerate(zip(keys, labels)):
            val = metrics.get(key, 0)
            y   = 0.7 - j * 0.16
            ax.text(0.15, y, f'{label}:',
                    ha='left', va='center', fontsize=10,
                    color='#8b949e', transform=ax.transAxes)
            ax.text(0.85, y, f'{val*100:.2f}%',
                    ha='right', va='center', fontsize=11,
                    color=color, fontweight='bold',
                    transform=ax.transAxes)

        if 'auc' in metrics:
            ax.text(0.15, 0.06, 'AUC-ROC:',
                    ha='left', va='center', fontsize=10,
                    color='#8b949e', transform=ax.transAxes)
            ax.text(0.85, 0.06, f'{metrics["auc"]*100:.2f}%',
                    ha='right', va='center', fontsize=11,
                    color=C['yellow'], fontweight='bold',
                    transform=ax.transAxes)

        for spine in ax.spines.values():
            spine.set_edgecolor(color)
            spine.set_linewidth(2)

    # ── Bottom row: summary bars ───────────────────
    ax_sum = fig.add_subplot(2, 1, 2)
    all_metrics = ['Accuracy', 'Precision', 'Recall', 'F1 Score']
    x = np.arange(len(all_metrics))
    w = 0.28

    bars_if  = [if_m['acc'],   if_m['prec'],   if_m['rec'],  if_m['f1']]
    bars_rf  = [rf_m['acc'],   rf_m['prec'],   rf_m['rec'],  rf_m['f1']]
    bars_mul = [multi_m['acc'],multi_m.get('prec',0),
                multi_m.get('rec',0), multi_m['f1']]

    ax_sum.bar(x - w, bars_if,  w, label='Isolation Forest', color=C['purple'], alpha=0.85)
    ax_sum.bar(x,     bars_rf,  w, label='RF Binary',        color=C['blue'],   alpha=0.85)
    ax_sum.bar(x + w, bars_mul, w, label='RF Multi-class',   color=C['green'],  alpha=0.85)
    ax_sum.set_xticks(x)
    ax_sum.set_xticklabels(all_metrics, fontsize=11)
    ax_sum.set_ylim(0, 1.2)
    ax_sum.set_ylabel('Score')
    ax_sum.set_title('All Models Side-by-Side Comparison', color=C['blue'])
    ax_sum.legend(loc='upper right')
    ax_sum.grid(axis='y', alpha=0.3)

    plt.tight_layout()
    _save('11_complete_summary.png')


# ══════════════════════════════════════════════════════════════════
# PREDICT FUNCTION — used by the dashboard at runtime
# ══════════════════════════════════════════════════════════════════
def predict_live(raw_features: dict) -> dict:
    """
    Called by dashboard/main.py for each new honeypot event.
    Input:  raw feature dict from the honeypot
    Output: full prediction with MITRE ATT&CK mapping
    """
    scaler       = joblib.load(os.path.join(MODEL_DIR, 'scaler.pkl'))
    rf_binary    = joblib.load(os.path.join(MODEL_DIR, 'rf_binary.pkl'))
    rf_multi     = joblib.load(os.path.join(MODEL_DIR, 'rf_multiclass.pkl'))
    le_attack    = joblib.load(os.path.join(MODEL_DIR, 'label_encoder.pkl'))
    feature_cols = joblib.load(os.path.join(MODEL_DIR, 'feature_cols.pkl'))
    iforest      = joblib.load(os.path.join(MODEL_DIR, 'isolation_forest.pkl'))

    vec        = pd.DataFrame([raw_features]).reindex(columns=feature_cols, fill_value=0)
    vec_scaled = scaler.transform(vec)

    # Isolation Forest anomaly score
    if_score   = float(iforest.score_samples(vec_scaled)[0])
    is_anomaly = iforest.predict(vec_scaled)[0] == -1

    # Binary: is it an attack?
    is_attack   = bool(rf_binary.predict(vec_scaled)[0])
    attack_prob = float(rf_binary.predict_proba(vec_scaled)[0][1])

    # Multi-class: what type?
    attack_type = 'Normal'
    mitre       = []
    if is_attack:
        enc         = rf_multi.predict(vec_scaled)[0]
        attack_type = le_attack.inverse_transform([enc])[0]
        mitre       = MITRE_MAP.get(attack_type, [])

    # Severity
    high_risk = {'Exploits', 'Backdoor', 'Shellcode', 'Worms'}
    if attack_type in high_risk or attack_prob >= 0.9:
        severity = 'CRITICAL'
    elif attack_prob >= 0.7:
        severity = 'HIGH'
    elif attack_prob >= 0.5:
        severity = 'MEDIUM'
    else:
        severity = 'LOW'

    return {
        'is_attack':          is_attack,
        'attack_probability': round(attack_prob * 100, 1),
        'attack_type':        attack_type,
        'anomaly_score':      round(if_score, 4),
        'is_anomaly':         is_anomaly,
        'mitre_tactics':      mitre,
        'severity':           severity,
        'features':           raw_features,
    }


# ══════════════════════════════════════════════════════════════════
# HELPER: Save plot
# ══════════════════════════════════════════════════════════════════
def _save(name: str):
    path = os.path.join(PLOT_DIR, name)
    plt.savefig(path, dpi=150, bbox_inches='tight', facecolor='#0d1117')
    plt.close()
    ok(f"Plot saved: {name}")


# ══════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════
if __name__ == '__main__':

    print("\n" + "╔" + "═"*62 + "╗")
    print("║" + "  HoneyTrack ML Engine — Full Training Pipeline".center(62) + "║")
    print("║" + "  UNSW-NB15 Dataset  |  3 Models  |  11 Plots".center(62) + "║")
    print("╚" + "═"*62 + "╝")

    # Step 1
    df = step1_load(DATA_PATH)

    # Step 2
    (X_tr, X_te, y_tr, y_te,
     ym_tr, ym_te, le_atk,
     feat_cols, scaler, encoders) = step2_preprocess(df)

    # Step 3 — Isolation Forest
    iforest, if_preds, if_scores, if_m = step3_isolation_forest(
        X_tr, X_te, y_tr, y_te, feat_cols
    )

    # Step 4 — RF Binary
    rf_bin, bin_preds, bin_probs, rf_m = step4_rf_binary(
        X_tr, X_te, y_tr, y_te, feat_cols
    )

    # Step 5 — RF Multi-class
    rf_multi, multi_preds, multi_m = step5_rf_multiclass(
        X_tr, X_te, y_tr, y_te,
        ym_tr, ym_te, le_atk
    )

    # Step 6 — Comparison
    step6_comparison(if_m, rf_m, multi_m)

    # Step 7 — MITRE
    step7_mitre(df)

    # Step 8 — Summary
    step8_summary(if_m, rf_m, multi_m)

    # Save results CSV
    results = pd.DataFrame([
        {
            'Model':     'Isolation Forest (Unsupervised)',
            'Accuracy':  f"{if_m['acc']*100:.2f}%",
            'Precision': f"{if_m['prec']*100:.2f}%",
            'Recall':    f"{if_m['rec']*100:.2f}%",
            'F1 Score':  f"{if_m['f1']*100:.2f}%",
            'AUC-ROC':   'N/A',
            'Note':      'Trained on normal traffic only',
        },
        {
            'Model':     'Random Forest Binary (Supervised)',
            'Accuracy':  f"{rf_m['acc']*100:.2f}%",
            'Precision': f"{rf_m['prec']*100:.2f}%",
            'Recall':    f"{rf_m['rec']*100:.2f}%",
            'F1 Score':  f"{rf_m['f1']*100:.2f}%",
            'AUC-ROC':   f"{rf_m['auc']*100:.2f}%",
            'Note':      'Normal vs Attack classification',
        },
        {
            'Model':     'Random Forest Multi-class (Supervised)',
            'Accuracy':  f"{multi_m['acc']*100:.2f}%",
            'Precision': 'N/A',
            'Recall':    'N/A',
            'F1 Score':  f"{multi_m['f1']*100:.2f}%",
            'AUC-ROC':   'N/A',
            'Note':      'Attack type classification (9 categories)',
        },
    ])
    results.to_csv(os.path.join(PLOT_DIR, 'final_results.csv'), index=False)

    # ── Final Summary ─────────────────────────────
    print("\n" + "╔" + "═"*62 + "╗")
    print("║" + "  TRAINING COMPLETE".center(62) + "║")
    print("╠" + "═"*62 + "╣")
    print(f"║  Isolation Forest   Accuracy : {if_m['acc']*100:6.2f}%          {'':>10}║")
    print(f"║  Isolation Forest   Precision: {if_m['prec']*100:6.2f}%          {'':>10}║")
    print(f"║  Isolation Forest   F1 Score : {if_m['f1']*100:6.2f}%          {'':>10}║")
    print("╠" + "═"*62 + "╣")
    print(f"║  Random Forest      Accuracy : {rf_m['acc']*100:6.2f}%          {'':>10}║")
    print(f"║  Random Forest      Precision: {rf_m['prec']*100:6.2f}%          {'':>10}║")
    print(f"║  Random Forest      F1 Score : {rf_m['f1']*100:6.2f}%          {'':>10}║")
    print(f"║  Random Forest      AUC-ROC  : {rf_m['auc']*100:6.2f}%          {'':>10}║")
    print("╠" + "═"*62 + "╣")
    print(f"║  RF Multi-class     Accuracy : {multi_m['acc']*100:6.2f}%          {'':>10}║")
    print(f"║  RF Multi-class     F1 Score : {multi_m['f1']*100:6.2f}%          {'':>10}║")
    print("╠" + "═"*62 + "╣")
    print(f"║  Models → {MODEL_DIR[-40:]}  ║")
    print(f"║  Plots  → {PLOT_DIR[-40:]}   ║")
    print("╚" + "═"*62 + "╝\n")
