import joblib

# Load the model
model = joblib.load("/home/abhishek/Documents/intrusion_detection/model/MLDF_model_lightgbm_optimized.joblib")

# Print feature names
print(model.feature_name())
