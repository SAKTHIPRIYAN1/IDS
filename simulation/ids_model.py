import pandas as pd
import joblib
import numpy as np
import sys

# --- 1. Load the Saved Models and "Knowledge" ---
print("Loading models and metadata...")

try:
    # Models
    rf_model = joblib.load("../model/rf_model.joblib")
    if_model = joblib.load("../model/if_model.joblib")
    
    # Scalers
    scaler_rf = joblib.load("../model/scaler_rf.joblib")
    scaler_if = joblib.load("../model/scaler_if.joblib")
    
    # Metadata
    saved_modes = joblib.load("../model/categorical_modes.joblib")
    saved_medians = joblib.load("../model/numeric_medians.joblib")
    saved_features = joblib.load("../model/feature_columns.joblib")
    saved_cat_cols = joblib.load("../model/categorical_cols.joblib")
    saved_num_cols = joblib.load("../model/numeric_fill_cols.joblib")

    print("Artifacts loaded successfully.\n")

except FileNotFoundError as e:
    print(f"Error: Could not load files. Make sure you ran the 'Saving' cell first.\n{e}")
    sys.exit(1)



ANOMALY_THRESHOLD = -0.1
SIGNATURE_THRESHOLD = 0.78


# --- 3. The Live Prediction Function ---
def check_hybrid_intrusion_live(X):
    """
    Input: X (Dictionary of features)
    Returns: Tuple (isIntrusion, reason, score)
    """
    
    # A. Create DataFrame from input
    # Handles both Dict and single-row DataFrame inputs
    if isinstance(X, dict):
        df = pd.DataFrame([X])
    else:
        df = X.copy()
    
    # B. Filter Input Columns 
    expected_cols = saved_cat_cols + saved_num_cols
    cols_to_use = [c for c in expected_cols if c in df.columns]
    df = df[cols_to_use]
    
    # C. Impute Categorical Data
    for col in saved_cat_cols:
        if col in df.columns:
            fill_val = saved_modes.get(col, "Unknown")
            df[col] = df[col].fillna(fill_val)
            
    # D. Impute Numerical Data
    for col in saved_num_cols:
        if col in df.columns:
            fill_val = saved_medians.get(col, 0)
            df[col] = df[col].fillna(fill_val)
            
    # E. One-Hot Encoding
    df = pd.get_dummies(df, columns=[c for c in saved_cat_cols if c in df.columns], dummy_na=False)
    
    # F. Feature Alignment
    df_aligned = df.reindex(columns=saved_features, fill_value=0)
    
    # --- G. Prediction ---
    
    # 1. Random Forest (Signature)
    X_rf = scaler_rf.transform(df_aligned)
    X_rf_df = pd.DataFrame(X_rf, columns=saved_features)
    prob_attack = rf_model.predict_proba(X_rf_df)[:, 1][0]
    
    # 2. Isolation Forest (Anomaly)
    X_if = scaler_if.transform(df_aligned)
    anomaly_score = if_model.decision_function(X_if)[0]
    
    # --- H. Hybrid Logic & Return Tuple ---
    
    print(f"Debug: prob_attack={prob_attack}, anomaly_score={anomaly_score}, X={X}")

    # Case 1: Signature Match (High Confidence Attack)
    if prob_attack >= SIGNATURE_THRESHOLD:
        return True, "Signature Match", prob_attack

    # Case 2: Anomaly Detected (Zero-Day Attack)
    elif anomaly_score <= ANOMALY_THRESHOLD:
        return True, "Anomaly Detected", anomaly_score

    # Case 3: Normal Traffic
    return False, "Normal", prob_attack
