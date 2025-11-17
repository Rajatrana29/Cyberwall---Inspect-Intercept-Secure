from flask import Flask, request, jsonify
from flask_cors import CORS
import os

app = Flask(__name__)
CORS(app)

UPLOAD_FOLDER = "../demo_files"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/scan', methods=['POST'])
def scan_file():
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
x