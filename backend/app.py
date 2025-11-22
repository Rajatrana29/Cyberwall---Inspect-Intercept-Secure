from flask import Flask, request, jsonify
from flask_cors import CORS
import os
from heuristics import HeuristicEngine

app = Flask(__name__)
CORS(app)

DB_PATH = "/home/rajat/cyberwall/backend/database/step1.db"
engine = HeuristicEngine(DB_PATH)

# Clean and consistent upload folder
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "..", "demo_files")
UPLOAD_FOLDER = os.path.abspath(UPLOAD_FOLDER)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/scan', methods=['POST'])
def scan():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)

    # Simple “fake scan” logic — later you can replace with VirusTotal or your ML model
    is_malicious = "virus" in file.filename.lower()

    result = {
        "filename": file.filename,
        "status": "Malicious" if is_malicious else "Safe"
    }

    return jsonify(result)

@app.route('/')
def home():
    return "Flask backend is running successfully!"

if __name__ == '__main__':
    app.run(debug=True)
