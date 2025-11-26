import React, { useState, useEffect } from "react";
import axios from "axios";
import "./App.css";

function App() {
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);

  useEffect(() => {
    const saved = JSON.parse(localStorage.getItem("scanHistory") || "[]");
    setHistory(saved);
  }, []);

  const handleFileChange = (e) => {
    setFile(e.target.files[0]);
  };

  const handleUpload = async () => {
    if (!file) {
      alert("Please select a file first!");
      return;
    }

    const formData = new FormData();
    formData.append("file", file);

    const res = await axios.post("http://127.0.0.1:5000/scan", formData, {
      headers: { "Content-Type": "multipart/form-data" },
    });

    setResult(res.data);
  };

  return (
    <div style={{ padding: "50px", fontFamily: "sans-serif" }}>
      <h1>CyberWall File Scanner</h1>
      <input type="file" onChange={handleFileChange} />
      <button onClick={handleUpload}>Scan</button>

      {result && (
        <div style={{ marginTop: "20px" }}>
          <h3>Result</h3>
          <p><strong>Filename:</strong> {result.filename}</p>
          <p><strong>Status:</strong> {result.status}</p>
        </div>
      )}
    </div>
  );
}

export default App;
