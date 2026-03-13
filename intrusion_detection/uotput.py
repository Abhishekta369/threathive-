import joblib
import numpy as np

# Load your LightGBM model
model = joblib.load("/home/abhishek/Documents/intrusion_detection/model/MLDF_model_lightgbm_optimized.joblib")

# Generate a dummy input (78 integer features)
sample_input = np.random.randint(0, 100, size=(1, 78))

# Get the model's output
output = model.predict(sample_input)

print(output)
predicted_class = np.argmax(output)
print(predicted_class)
