import pandas as pd
import joblib
import numpy as np
import shap
import os

# ---- CONFIGURATION ----
# Thresholds must match what you tuned in the notebook
SIGNATURE_THRESHOLD = 0.65   # RF Threshold
ANOMALY_THRESHOLD   = -0.05 # IF Threshold

print("[IDS] Loading models and pipeline components...")

# Load models and preprocessing artifacts
folder = "./model/tmp"
try:
    rf_model = joblib.load(f"{folder}/rf_model.joblib")
    if_model = joblib.load(f"{folder}/if_model.joblib")
    scaler   = joblib.load(f"{folder}/scaler.joblib")
    vt       = joblib.load(f"{folder}/variance_threshold.joblib")
    
    # 'saved_features' here refers to the FULL list of encoded columns 
    # required to align the dataframe before VarianceThreshold
    saved_features = joblib.load(f"{folder}/feature_columns.joblib")
    
    print("[IDS] Components loaded successfully.")
except FileNotFoundError as e:
    print(f"[ERROR] Could not load pipeline files from '{folder}/'. Ensure you ran the save function first.")
    raise e

# Initialize SHAP Explainers
# Note: RF Explainer is fast. IF Explainer can be slower; we init it here.
rf_explainer = shap.TreeExplainer(rf_model)
if_explainer = shap.TreeExplainer(if_model)


# ---- 1. PREPROCESSING FUNCTION ----
def preprocess(raw):
    """
    Converts raw dictionary input into the EXACT format the model expects:
    1. DF creation
    2. One-Hot Encoding (aligned to training columns)
    3. VarianceThreshold
    4. Scaling
    """
    # 1. Convert dict to DataFrame
    df = pd.DataFrame([raw])

    # 2. One-Hot Encoding & Alignment
    # We use reindex to add missing columns (filled with 0) and drop extra ones
    df_encoded = pd.get_dummies(df)
    df_aligned = df_encoded.reindex(columns=saved_features, fill_value=0)

    # 3. Apply Variance Threshold (Transform ONLY)
    X_vt = vt.transform(df_aligned)

    # 4. Apply Standard Scaler (Transform ONLY)
    X_scaled = scaler.transform(X_vt)
    
    print("Raw Data:", raw)
    # Return the scaled array (for prediction)
    return X_scaled


# ---- 2. XAI EXPLANATION FUNCTION ----
def explain_decision(X_scaled, intrusion_flag, confidence_score, detection_type="RF/IDS"):
    """
    Robust XAI explanation that handles different SHAP output formats.
    """
    
    if not intrusion_flag:
        return "Normal Traffic: No anomaly detected.", None


    try:
        feature_indices = vt.get_support(indices=True)
        active_feature_names = [saved_features[i] for i in feature_indices]
    except Exception as e:
        return f"XAI Setup Failed (Feature Mapping): {str(e)}", None

    context_msg = ""
    explanations = []

    try:

        if detection_type == "Signature matched" or detection_type == "RF/IDS":
            context_msg = f"<b>[RF Alert]</b> flagged threat ({confidence_score:.1f}% confidence)."
            
            shap_vals = rf_explainer.shap_values(X_scaled)
            
            # --- ROBUST SHAP HANDLING ---
            if isinstance(shap_vals, list):
                # If list has 2 items (Class 0, Class 1), take Class 1 (Attack)
                if len(shap_vals) > 1:
                    values = shap_vals[1]
                else:
                    # If list has 1 item, take it
                    values = shap_vals[0]
            else:
                # If it's a raw numpy array
                values = shap_vals
            
            # Flatten to ensures 1D array (e.g., from shape (1, 22) to (22,))
            # We access [0] if it's still 2D
            if len(values.shape) == 2:
                values = values[0]
            
            values = values.flatten()
            # ----------------------------

            # Find top 3 contributing features
            top_indices = np.argsort(np.abs(values))[::-1][:3]
            
            for i in top_indices:
                # Safety check for index
                if i < len(active_feature_names):
                    feat_name = active_feature_names[i]
                    impact = values[i]
                    direction = "increased risk" if impact > 0 else "offset risk"
                    explanations.append(f"<b>{feat_name}</b> {direction} ({impact:+.2f})")

        # CASE B: Isolation Forest Explanation (Anomaly)
        elif detection_type == "Anomaly detected" or detection_type == "IF/IDS":
            context_msg = f"<b>[Anomaly Alert]</b> flagged outlier (Score: {confidence_score:.3f})."
            
            shap_vals_if = if_explainer.shap_values(X_scaled)
            
            # Handle IF SHAP shape
            if isinstance(shap_vals_if, list):
                 values = shap_vals_if[0]
            else:
                 values = shap_vals_if
            
            if len(values.shape) == 2:
                values = values[0]
            values = values.flatten()
            
            top_indices = np.argsort(np.abs(values))[::-1][:3]
            
            for i in top_indices:
                if i < len(active_feature_names):
                    feat_name = active_feature_names[i]
                    impact = values[i]
                    explanations.append(f"<b>{feat_name}</b> contrib: {impact:.2f}")

    except Exception as e:
        # This will print the exact error for debugging if it still fails
        import traceback
        traceback.print_exc() 
        return f"XAI Analysis Failed: {str(e)}", None

    final_report = f"{context_msg} Top factors: {', '.join(explanations)}"
    
    return final_report, None

# ---- 3. MAIN PREDICTION FUNCTION ----
def check_hybrid_intrusion_live(raw_row):
    """
    Main entry point. 
    Returns: (is_intrusion, status_message, score, explanation_text, plot_object)
    """
    # 1. Preprocess
    # Returns 2D array: (1, n_features)
    X_scaled = preprocess(raw_row) 
    
    # 2. Random Forest Prediction (Signature)
    rf_prob = rf_model.predict_proba(X_scaled)[:, 1][0]
    
    # 3. Isolation Forest Prediction (Anomaly)
    if_score = if_model.decision_function(X_scaled)[0]
    
    # 4. Check Logic
    print("i think  it is Rf:", rf_prob )
    # Priority 1: Known Signature (RF)
    if rf_prob >= SIGNATURE_THRESHOLD:
        exp, plot = explain_decision(X_scaled, True, rf_prob * 100, detection_type="RF/IDS")
        return True, "Signature matched", rf_prob, exp, plot
    print("No rf")
    # Priority 2: Anomaly (IF)
    if if_score <= ANOMALY_THRESHOLD:
        # Pass raw score for context
        exp, plot = explain_decision(X_scaled, True, if_score, detection_type="IF/IDS") 
        return True, "Anomaly detected", if_score, exp, plot
    print("NO if")
    # Default: Normal
    return False, "Normal traffic pattern", 0.0, None, None