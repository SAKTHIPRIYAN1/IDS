

import pandas as pd
import joblib
import numpy as np
import shap
import matplotlib.pyplot as plt

SIGNATURE_THRESHOLD = 0.72
ANOMALY_THRESHOLD   = -0.1

print("[IDS] Loading models...")

rf_model   = joblib.load("model/rf_model.joblib")
if_model   = joblib.load("model/if_model.joblib")

scaler_rf  = joblib.load("model/scaler_rf.joblib")
scaler_if  = joblib.load("model/scaler_if.joblib")

saved_modes    = joblib.load("model/categorical_modes.joblib")
saved_medians  = joblib.load("model/numeric_medians.joblib")
saved_features = joblib.load("model/feature_columns.joblib")
saved_cat_cols = joblib.load("model/categorical_cols.joblib")
saved_num_cols = joblib.load("model/numeric_fill_cols.joblib")

rf_explainer = shap.TreeExplainer(rf_model)

print("[IDS] Models loaded")

# preProcess
def preprocess(raw):
    df = pd.DataFrame([raw])

    for c in saved_cat_cols:
        df[c] = df.get(c, saved_modes.get(c, "Unknown"))

    for c in saved_num_cols:
        df[c] = df.get(c, saved_medians.get(c, 0))

    df = pd.get_dummies(df, columns=saved_cat_cols)
    df = df.reindex(columns=saved_features, fill_value=0)

    return df


def explain_decision(X_scaled, intrusion_flag, confidence_score, detection_type="RF/IDS"):

    if not intrusion_flag and confidence_score < 50:
        return "Normal Traffic: No anomaly detected."

    context_msg = f"<b>[{detection_type}]</b> flagged threat ({confidence_score:.1f}% confidence)."

    try:
        shap_vals = rf_explainer.shap_values(X_scaled)

        if isinstance(shap_vals, list):
            values = shap_vals[1][0]
        elif len(shap_vals.shape) == 3:
            values = shap_vals[0, :, 1]
        else:
            values = shap_vals[0]

        top_indices = np.argsort(np.abs(values))[::-1][:3]

    except Exception as e:
        return f"XAI Analysis Failed: {str(e)}"

    explanations = []

    for i in top_indices:
        feature_name = saved_features[i]
        impact = values[i]

        if impact > 0:
            explanations.append(
                f"High <b>{feature_name}</b> increased risk (+{impact:.2f})"
            )
        else:
            explanations.append(
                f"Low <b>{feature_name}</b> offset risk ({impact:.2f})"
            )

    final_report = f"{context_msg} Top factors: {', '.join(explanations)}"

    return final_report,None

def check_hybrid_intrusion_live(raw_row):
    df = preprocess(raw_row)

    X_rf = scaler_rf.transform(df)
    X_rf_df = pd.DataFrame(X_rf, columns=saved_features)

    prob = rf_model.predict_proba(X_rf_df)[:, 1][0]

    X_if = scaler_if.transform(df)
    score_if = if_model.decision_function(X_if)[0]

    if prob >= SIGNATURE_THRESHOLD:
        exp, plot = explain_decision(X_rf_df, True, prob * 100)
        return True, "Signature matched", prob, exp, plot

    if score_if <= ANOMALY_THRESHOLD:
        exp, plot = explain_decision(X_rf_df, True, score_if * 100, detection_type="IF/IDS")
        return True, "Anomaly detected", score_if, exp, plot

    return False, "Normal traffic pattern", None, None, None
