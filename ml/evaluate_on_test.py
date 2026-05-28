"""
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║        HoneyTrack — ML Model Evaluation on Test Set              ║
║                                                                  ║
║        Jordan University of Science and Technology               ║
║        Faculty of Computer and Information Technology            ║
║        Capstone Project — 2026                                   ║
║                                                                  ║
║  ── What this file does ─────────────────────────────────────── ║
║  1.  Loads the pre-trained models from models/                  ║
║  2.  Loads ONLY the test set (UNSW_NB15_testing-set.csv)        ║
║  3.  Evaluates models on UNSEEN data                             ║
║  4.  Saves evaluation results and plots                          ║
║                                                                  ║
║  USAGE:                                                          ║
║      python evaluate_on_test.py                                  ║
║                                                                  ║
║  OUTPUT:                                                         ║
║      test_results/  → Evaluation results and plots              ║
╚══════════════════════════════════════════════════════════════════╝
"""

# ── Standard Library ──────────────────────────────────────────────
import os
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
import seaborn as sns

# ── Machine Learning ──────────────────────────────────────────────
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, roc_curve,
    confusion_matrix, classification_report
)

# ══════════════════════════════════════════════════════════════════
# CONFIGURATION
# ══════════════════════════════════════════════════════════════════
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR  = os.path.join(BASE_DIR, 'models')
TEST_PATH  = os.path.join(BASE_DIR, 'UNSW_NB15_testing-set.csv')
OUTPUT_DIR = os.path.join(BASE_DIR, 'test_results')
os.makedirs(OUTPUT_DIR, exist_ok=True)

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
    'font.size':        11,
})

C = {
    'blue':   '#58a6ff',
    'green':  '#3fb950',
    'red':    '#f85149',
    'yellow': '#d29922',
    'purple': '#bc8cff',
    'orange': '#f0883e',
    'muted':  '#8b949e',
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


def section(title):
    print(f"\n{'═'*64}")
    print(f"  {title}")
    print(f"{'═'*64}")


def ok(msg):
    print(f"  ✔  {msg}")


def info(msg):
    print(f"  ●  {msg}")


def _save(name, fig):
    path = os.path.join(OUTPUT_DIR, name)
    fig.savefig(path, dpi=150, bbox_inches='tight', facecolor='#0d1117')
    plt.close(fig)
    ok(f"Plot saved: {name}")


# ══════════════════════════════════════════════════════════════════
# STEP 1 — LOAD MODELS
# ══════════════════════════════════════════════════════════════════
def step1_load_models():
    section("STEP 1 — Loading Pre-trained Models")

    scaler = joblib.load(os.path.join(MODEL_DIR, 'scaler.pkl'))
    encoders = joblib.load(os.path.join(MODEL_DIR, 'encoders.pkl'))
    le_attack = joblib.load(os.path.join(MODEL_DIR, 'label_encoder.pkl'))
    feature_cols = joblib.load(os.path.join(MODEL_DIR, 'feature_cols.pkl'))
    iforest = joblib.load(os.path.join(MODEL_DIR, 'isolation_forest.pkl'))
    rf_binary = joblib.load(os.path.join(MODEL_DIR, 'rf_binary.pkl'))
    rf_multiclass = joblib.load(os.path.join(MODEL_DIR, 'rf_multiclass.pkl'))

    ok("All 7 models loaded successfully")
    ok(f"Feature columns: {len(feature_cols)} features")
    ok(f"Attack categories: {list(le_attack.classes_)}")

    return {
        'scaler': scaler,
        'encoders': encoders,
        'le_attack': le_attack,
        'feature_cols': feature_cols,
        'iforest': iforest,
        'rf_binary': rf_binary,
        'rf_multiclass': rf_multiclass,
    }


# ══════════════════════════════════════════════════════════════════
# STEP 2 — LOAD & PREPARE TEST DATA
# ══════════════════════════════════════════════════════════════════
def step2_load_test_data(models):
    section("STEP 2 — Loading Test Set (UNSEEN Data)")

    df = pd.read_csv(TEST_PATH)
    ok(f"Loaded: {len(df):,} rows × {df.shape[1]} columns")

    # Drop ID column if exists
    df.drop(columns=['id'], inplace=True, errors='ignore')

    # Encode categorical columns
    encoders = models['encoders']
    for col in ['proto', 'service', 'state']:
        if col in df.columns:
            df[col] = encoders[col].transform(df[col].astype(str))

    # Add engineered features (same as training)
    df['byte_ratio'] = df['sbytes'] / (df['dbytes'] + 1)
    df['pkt_diff'] = df['spkts'] - df['dpkts']
    df['load_ratio'] = df['sload'] / (df['dload'] + 1)
    df['jit_ratio'] = df['sjit'] / (df['djit'] + 1)
    df['conn_intensity'] = df['ct_srv_src'] * df['ct_srv_dst']

    # Prepare features
    feature_cols = models['feature_cols']
    X = df[feature_cols]
    y_binary = df['label']
    y_multi = df['attack_cat']

    # Scale features
    scaler = models['scaler']
    X_scaled = scaler.transform(X)

    ok(f"Test set prepared: {X_scaled.shape[0]:,} samples")
    info(f"Attack samples: {(y_binary == 1).sum():,}")
    info(f"Normal samples: {(y_binary == 0).sum():,}")

    return X_scaled, y_binary, y_multi, df


# ══════════════════════════════════════════════════════════════════
# STEP 3 — EVALUATE ISOLATION FOREST
# ══════════════════════════════════════════════════════════════════
def step3_evaluate_iforest(models, X_test, y_test):
    section("STEP 3 — Isolation Forest Evaluation")

    iforest = models['iforest']
    preds_raw = iforest.predict(X_test)
    if_preds = (preds_raw == -1).astype(int)
    if_scores = iforest.score_samples(X_test)

    acc = accuracy_score(y_test, if_preds)
    prec = precision_score(y_test, if_preds, zero_division=0)
    rec = recall_score(y_test, if_preds, zero_division=0)
    f1 = f1_score(y_test, if_preds, zero_division=0)

    print(f"\n  ┌{'─'*42}┐")
    print(f"  │{'Isolation Forest on TEST SET':^42}│")
    print(f"  ├{'─'*42}┤")
    print(f"  │  Accuracy   : {acc*100:>6.2f}%{' '*24}│")
    print(f"  │  Precision  : {prec*100:>6.2f}%{' '*24}│")
    print(f"  │  Recall     : {rec*100:>6.2f}%{' '*24}│")
    print(f"  │  F1 Score   : {f1*100:>6.2f}%{' '*24}│")
    print(f"  └{'─'*42}┘")
    info("Note: Low accuracy is EXPECTED for unsupervised models (trained only on normal traffic)")

    # Plot
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    fig.suptitle('Isolation Forest — Test Set Results',
                 color=C['purple'], fontsize=14, fontweight='bold')

    normal_scores = if_scores[y_test.values == 0]
    attack_scores = if_scores[y_test.values == 1]

    axes[0].hist(normal_scores, bins=60, alpha=0.7, color=C['green'],
                 label='Normal', edgecolor='none', density=True)
    axes[0].hist(attack_scores, bins=60, alpha=0.7, color=C['red'],
                 label='Attack', edgecolor='none', density=True)
    axes[0].set_title('Anomaly Score Distribution')
    axes[0].set_xlabel('Anomaly Score (lower = more anomalous)')
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
    _save('01_iforest_test_results.png', fig)

    return {'acc': acc, 'prec': prec, 'rec': rec, 'f1': f1}


# ══════════════════════════════════════════════════════════════════
# STEP 4 — EVALUATE RF BINARY
# ══════════════════════════════════════════════════════════════════
def step4_evaluate_rf_binary(models, X_test, y_test):
    section("STEP 4 — Random Forest Binary Evaluation")

    rf_bin = models['rf_binary']
    preds = rf_bin.predict(X_test)
    probs = rf_bin.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, preds)
    prec = precision_score(y_test, preds, zero_division=0)
    rec = recall_score(y_test, preds, zero_division=0)
    f1 = f1_score(y_test, preds, zero_division=0)
    auc = roc_auc_score(y_test, probs)

    print(f"\n  ┌{'─'*42}┐")
    print(f"  │{'Random Forest Binary on TEST SET':^42}│")
    print(f"  ├{'─'*42}┤")
    print(f"  │  Accuracy   : {acc*100:>6.2f}%{' '*24}│")
    print(f"  │  Precision  : {prec*100:>6.2f}%{' '*24}│")
    print(f"  │  Recall     : {rec*100:>6.2f}%{' '*24}│")
    print(f"  │  F1 Score   : {f1*100:>6.2f}%{' '*24}│")
    print(f"  │  AUC-ROC    : {auc*100:>6.2f}%{' '*24}│")
    print(f"  └{'─'*42}┘")

    # Plot
    fig, axes = plt.subplots(1, 2, figsize=(14, 6))
    fig.suptitle('Random Forest Binary — Test Set Results',
                 color=C['blue'], fontsize=14, fontweight='bold')

    cm = confusion_matrix(y_test, preds)
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=axes[0],
                xticklabels=['Normal', 'Attack'],
                yticklabels=['Normal', 'Attack'],
                linewidths=0.5, annot_kws={'size': 14})
    axes[0].set_title(f'Confusion Matrix (Accuracy: {acc*100:.2f}%)')
    axes[0].set_xlabel('Predicted')
    axes[0].set_ylabel('Actual')

    fpr, tpr, _ = roc_curve(y_test, probs)
    axes[1].plot(fpr, tpr, color=C['blue'], lw=2.5,
                 label=f'ROC Curve (AUC = {auc:.4f})')
    axes[1].plot([0, 1], [0, 1], color=C['muted'], lw=1,
                 linestyle='--', label='Random Classifier')
    axes[1].fill_between(fpr, tpr, alpha=0.1, color=C['blue'])
    axes[1].set_title('ROC Curve')
    axes[1].set_xlabel('False Positive Rate')
    axes[1].set_ylabel('True Positive Rate')
    axes[1].legend(loc='lower right')
    axes[1].grid(True, alpha=0.3)

    plt.tight_layout()
    _save('02_rf_binary_test_results.png', fig)

    return {'acc': acc, 'prec': prec, 'rec': rec, 'f1': f1, 'auc': auc}


# ══════════════════════════════════════════════════════════════════
# STEP 5 — EVALUATE RF MULTI-CLASS
# ══════════════════════════════════════════════════════════════════
def step5_evaluate_rf_multiclass(models, X_test, y_test_bin, y_test_multi):
    section("STEP 5 — Random Forest Multi-class Evaluation")

    # Filter only attack samples
    attack_mask = y_test_bin == 1
    X_attack = X_test[attack_mask]
    y_attack_enc = models['le_attack'].transform(y_test_multi[attack_mask])

    if len(X_attack) == 0:
        info("No attack samples in test set")
        return {'acc': 0, 'f1': 0}

    rf_multi = models['rf_multiclass']
    preds = rf_multi.predict(X_attack)
    acc = accuracy_score(y_attack_enc, preds)
    f1 = f1_score(y_attack_enc, preds, average='weighted', zero_division=0)

    print(f"\n  ┌{'─'*42}┐")
    print(f"  │{'Random Forest Multi-class on TEST SET':^42}│")
    print(f"  ├{'─'*42}┤")
    print(f"  │  Accuracy     : {acc*100:>6.2f}%{' '*22}│")
    print(f"  │  F1 (weighted): {f1*100:>6.2f}%{' '*22}│")
    print(f"  └{'─'*42}┘")

    # Classification report
    le_attack = models['le_attack']
    unique_labels = np.unique(np.concatenate([y_attack_enc, preds]))
    label_names = le_attack.inverse_transform(unique_labels)

    print("\n  Per-class Report:")
    print(classification_report(y_attack_enc, preds,
                                labels=unique_labels,
                                target_names=label_names,
                                zero_division=0))

    # Confusion matrix plot
    fig, ax = plt.subplots(figsize=(12, 9))
    cm = confusion_matrix(y_attack_enc, preds, labels=unique_labels)
    sns.heatmap(cm, annot=True, fmt='d', cmap='Purples', ax=ax,
                xticklabels=label_names, yticklabels=label_names,
                linewidths=0.5)
    ax.set_title('Multi-class Confusion Matrix — Test Set',
                 color=C['purple'], pad=15)
    ax.set_xlabel('Predicted Attack Type')
    ax.set_ylabel('Actual Attack Type')
    plt.xticks(rotation=30, ha='right')
    plt.tight_layout()
    _save('03_rf_multiclass_test_results.png', fig)

    # F1 score per class plot
    report = classification_report(y_attack_enc, preds,
                                   labels=unique_labels,
                                   target_names=label_names,
                                   output_dict=True, zero_division=0)
    classes = [k for k in report if k not in ('accuracy', 'macro avg', 'weighted avg')]
    f1_scores = [report[k]['f1-score'] for k in classes]
    supports = [report[k]['support'] for k in classes]
    colors = [ATTACK_COLORS.get(c, C['blue']) for c in classes]

    fig, axes = plt.subplots(1, 2, figsize=(16, 6))
    fig.suptitle('Multi-class Classification Results — Test Set',
                 color=C['purple'], fontsize=14, fontweight='bold')

    bars = axes[0].bar(classes, f1_scores, color=colors, edgecolor='none', width=0.6)
    axes[0].set_title('F1-Score per Attack Category')
    axes[0].set_ylabel('F1 Score')
    axes[0].set_ylim(0, 1.15)
    axes[0].axhline(y=f1, color=C['yellow'], linestyle='--', lw=1.5, label=f'Weighted F1: {f1:.3f}')
    axes[0].legend()
    for bar, val in zip(bars, f1_scores):
        axes[0].text(bar.get_x() + bar.get_width()/2, val + 0.02,
                     f'{val:.2f}', ha='center', fontsize=10)
    plt.setp(axes[0].xaxis.get_majorticklabels(), rotation=30, ha='right')
    axes[0].grid(axis='y', alpha=0.3)

    axes[1].bar(classes, supports, color=colors, edgecolor='none', width=0.6)
    axes[1].set_title('Test Samples per Attack Category')
    axes[1].set_ylabel('Sample Count')
    for i, (c, v) in enumerate(zip(classes, supports)):
        axes[1].text(i, v + 50, f'{v:,}', ha='center', fontsize=9)
    plt.setp(axes[1].xaxis.get_majorticklabels(), rotation=30, ha='right')
    axes[1].grid(axis='y', alpha=0.3)

    plt.tight_layout()
    _save('04_f1_per_attack_type.png', fig)

    return {'acc': acc, 'f1': f1}


# ══════════════════════════════════════════════════════════════════
# STEP 6 — COMPARISON PLOT
# ══════════════════════════════════════════════════════════════════
def step6_comparison_plot(if_metrics, rf_metrics, multi_metrics):
    section("STEP 6 — Model Comparison Summary")

    fig, ax = plt.subplots(figsize=(14, 7))
    fig.suptitle('Model Performance Comparison — Test Set (Unseen Data)',
                 color=C['blue'], fontsize=14, fontweight='bold')

    metrics = ['Accuracy', 'Precision', 'Recall', 'F1 Score']
    x = np.arange(len(metrics))
    w = 0.25

    if_vals = [if_metrics['acc'], if_metrics['prec'], if_metrics['rec'], if_metrics['f1']]
    rf_vals = [rf_metrics['acc'], rf_metrics['prec'], rf_metrics['rec'], rf_metrics['f1']]
    multi_vals = [multi_metrics['acc'], 0, 0, multi_metrics['f1']]

    bars1 = ax.bar(x - w, if_vals, w, label='Isolation Forest', color=C['purple'], alpha=0.85)
    bars2 = ax.bar(x, rf_vals, w, label='RF Binary', color=C['blue'], alpha=0.85)
    bars3 = ax.bar(x + w, multi_vals, w, label='RF Multi-class', color=C['green'], alpha=0.85)

    ax.set_xticks(x)
    ax.set_xticklabels(metrics, fontsize=11)
    ax.set_ylim(0, 1.18)
    ax.set_ylabel('Score')
    ax.set_title('All Models Comparison on Test Set')
    ax.legend(loc='upper right')
    ax.grid(axis='y', alpha=0.3)

    for bars in [bars1, bars2, bars3]:
        for bar in bars:
            if bar.get_height() > 0:
                ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02,
                        f'{bar.get_height():.2f}', ha='center', fontsize=9)

    plt.tight_layout()
    _save('05_model_comparison_test_set.png', fig)


# ══════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════
if __name__ == '__main__':

    print("\n" + "╔" + "═"*62 + "╗")
    print("║" + "  HoneyTrack ML — Evaluation on Test Set".center(62) + "║")
    print("║" + "  Models trained on training-set".center(62) + "║")
    print("║" + "  Evaluated on testing-set (UNSEEN data)".center(62) + "║")
    print("╚" + "═"*62 + "╝")

    # Step 1: Load models
    models = step1_load_models()

    # Step 2: Load test data
    X_test, y_binary, y_multi, df = step2_load_test_data(models)

    # Step 3: Isolation Forest
    if_metrics = step3_evaluate_iforest(models, X_test, y_binary)

    # Step 4: RF Binary
    rf_metrics = step4_evaluate_rf_binary(models, X_test, y_binary)

    # Step 5: RF Multi-class
    multi_metrics = step5_evaluate_rf_multiclass(models, X_test, y_binary, y_multi)

    # Step 6: Comparison plot
    step6_comparison_plot(if_metrics, rf_metrics, multi_metrics)

    # Save results to CSV
    results = pd.DataFrame([
        {'Model': 'Isolation Forest (Unsupervised)',
         'Accuracy': f"{if_metrics['acc']*100:.2f}%",
         'Precision': f"{if_metrics['prec']*100:.2f}%",
         'Recall': f"{if_metrics['rec']*100:.2f}%",
         'F1 Score': f"{if_metrics['f1']*100:.2f}%",
         'AUC-ROC': 'N/A'},
        {'Model': 'Random Forest Binary (Supervised)',
         'Accuracy': f"{rf_metrics['acc']*100:.2f}%",
         'Precision': f"{rf_metrics['prec']*100:.2f}%",
         'Recall': f"{rf_metrics['rec']*100:.2f}%",
         'F1 Score': f"{rf_metrics['f1']*100:.2f}%",
         'AUC-ROC': f"{rf_metrics['auc']*100:.2f}%"},
        {'Model': 'Random Forest Multi-class (Supervised)',
         'Accuracy': f"{multi_metrics['acc']*100:.2f}%",
         'Precision': 'N/A',
         'Recall': 'N/A',
         'F1 Score': f"{multi_metrics['f1']*100:.2f}%",
         'AUC-ROC': 'N/A'},
    ])

    results.to_csv(os.path.join(OUTPUT_DIR, 'test_results.csv'), index=False)
    ok(f"Results saved to {OUTPUT_DIR}/test_results.csv")

    print("\n" + "╔" + "═"*62 + "╗")
    print("║" + "  EVALUATION COMPLETE".center(62) + "║")
    print("╠" + "═"*62 + "╣")
    print(f"║  Isolation Forest   Accuracy : {if_metrics['acc']*100:6.2f}%{' ':>25}║")
    print(f"║  Random Forest      Accuracy : {rf_metrics['acc']*100:6.2f}%{' ':>25}║")
    print(f"║  Random Forest      AUC-ROC  : {rf_metrics['auc']*100:6.2f}%{' ':>25}║")
    print(f"║  RF Multi-class     Accuracy : {multi_metrics['acc']*100:6.2f}%{' ':>25}║")
    print("╠" + "═"*62 + "╣")
    print(f"║  Results saved to: {OUTPUT_DIR[-35:]}             ║")
    print("╚" + "═"*62 + "╝\n")