#!/bin/bash
# Run inference script (or other necessary scripts)
python ai_threat_detection/ai_model_inference.py

# Start Flask app to keep the container running
python app.py

