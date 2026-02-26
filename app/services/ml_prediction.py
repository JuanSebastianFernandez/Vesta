import joblib
import numpy as np
import tensorflow as tf
from sklearn import pipeline, linear_model, preprocessing
from typing import Any
from app.core.config import settings
from app.core.exceptions import ModelLoadingError, AnalysisError
from app.services.feature_extractor import FEATURE_NAMES_ORDER

# Precharging models will be excecute one time when the application starts
svm_model: pipeline.Pipeline | None = None
cnn_model: tf.keras.Model | None = None # type: ignore
meta_model: linear_model.LogisticRegression| None = None
scaler: preprocessing.StandardScaler | None = None


# We need to load models Keras/Tensorflow saving
k = tf.keras # type: ignore
KL = k.layers
LM = k.models
loadModel = LM.load_model

def _load_all_models() -> None:
    """
    Load all ML models and scaler.
    """
    global svm_model, cnn_model, meta_model, scaler
    try:
        print(f"Loading scaler............")
        scaler = joblib.load(settings.SCALER_PATH)
        print(type(scaler))
        print("✅ Scaler loaded succesfully.")
        

        print(f"Loading SVM model...........")
        svm_model = joblib.load(settings.SVM_MODEL_PATH)
        print(type(svm_model))
        print("✅ SVM model loaded succesfully.")

        print(f"Loading CNN model............")
        cnn_model = loadModel(settings.CNN_MODEL_PATH)
        print(type(cnn_model))
        print("✅ CNN model loaded succesfully.")

        print(f"Loading meta model............")
        meta_model = joblib.load(settings.META_MODEL_PATH)
        print(type(meta_model))
        print("✅ Meta model loaded succesfully")


    except FileNotFoundError as e:
        raise ModelLoadingError(f"Model file not found: {e}. Please check the model paths in config.py are correct.")
    except Exception as e:
        raise ModelLoadingError(f"An error occurred while loading models: {e}")
    

# Execute load models when module is imported
_load_all_models()

def predict_malware_risk(raw_features: dict[str, float]) -> dict[str, Any]:
    """
    Make risk ransomware prediction using ML pipeline charged.

    Args:
        raw_features (dict[str, float]): A dictionary with 12 features (without scaler applied)

    Returns:
        dict[str, Any]: A dictionary with probability prediction and binary clasification.

    Raises:
        ModelLoadingError: When models are not loaded.
        AnalysisError: When there is a probelm with the input features.
    """

    if not all([svm_model, cnn_model, meta_model, scaler]):
        raise ModelLoadingError("All AI models are not loaded. The prediction isn't possible.")
    
    # Keep the order and format in the feature vector
    try:
        feature_vector = np.array([raw_features[name] for name in FEATURE_NAMES_ORDER])
        # Scaler need a 2D entry
        feature_vector_reshaped = feature_vector.reshape(1, -1)
        

    except KeyError as e:
        raise AnalysisError(f"Empty feature in entry vector: {e}. Make sure all 12 features are correct in the extraction process.")
    except Exception as e:
        raise AnalysisError(f"Error refactoring vector features for scaling process: {e}.")

    # Apply scaling
    scaled_features = scaler.transform(feature_vector_reshaped) # type: ignore

    # SVM prediction - SVM need vecto 1 row per 12 columns
    svm_pred_raw = svm_model.predict(scaled_features)[0]  # type: ignore

    # CNN prediction - input 4D (1, 12, 1, 1)
    cnn_input_reshaped = scaled_features.reshape(1, 12, 1, 1)
    cnn_pred_proba_raw = cnn_model.predict(cnn_input_reshaped).flatten()[0] # type: ignore

    # Combine predictions for the metamodel
    ensemble_input = np.array([[svm_pred_raw, cnn_pred_proba_raw]])

    # Predict using the metamodel (Logistic Regression)
    ensemble_pred_prob = meta_model.predict_proba(ensemble_input)[:, 1][0] # type: ignore
    ensemble_pred_binary = (ensemble_pred_prob > 0.5).astype(int)

    return {
        "prediction_probability": float(ensemble_pred_prob),
        "prediction_binary": int(ensemble_pred_binary)
    }

if __name__ == "__main__":
    data_feature_tests =  [
        {
            "data":{
                        "SectionsMaxEntropy": 4.5218005080139445,
                        "SizeOfStackReserve": 3.0,
                        "SectionsMinVirtualsize": 86.0,
                        "ResourcesMinEntropy": 1.584962500721156,
                        "MajorLinkerVersion": 1.0,
                        "SizeOfOptionalHeader": 8.0,
                        "AddressOfEntryPoint": 1.0,
                        "SectionsMinEntropy": 3.4634121559101168,
                        "MinorOperatingSystemVersion": 0.0,
                        "SectionAlignment": 0.0,
                        "SizeOfHeaders": 8.0,
                        "LoaderFlags": 0.0
                    },
            "Value_expected": 1
        },
        {
            "data":{
                        "SectionsMaxEntropy": 6.296826,
                        "SizeOfStackReserve": 1048576,
                        "SectionsMinVirtualsize": 16468,
                        "ResourcesMinEntropy": 1.441688,
                        "MajorLinkerVersion": 11,
                        "SizeOfOptionalHeader": 224,
                        "AddressOfEntryPoint": 183632,
                        "SectionsMinEntropy": 2.378947,
                        "MinorOperatingSystemVersion": 1,
                        "SectionAlignment": 4096,
                        "SizeOfHeaders": 1024,
                        "LoaderFlags": 0
        },
            "Value_expected": 0
        }
    ]

    for data_test in data_feature_tests:
        data_feature_training = data_test["data"]
        value_expected = data_test["Value_expected"]

        returned = predict_malware_risk(data_feature_training)
        print(returned)
        if returned["prediction_binary"] == value_expected:
            print("Model was Right")
