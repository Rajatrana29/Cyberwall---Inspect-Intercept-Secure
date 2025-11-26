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
    saveToHistory(res.data);
  };

  const saveToHistory = (data) => {
    const newEntry = {
      filename: data.filename,
      status: data.status,
      score: data.score,
      time: new Date().toLocaleString(),
    };

    const updated = [newEntry, ...history];
    setHistory(updated);
    localStorage.setItem("scanHistory", JSON.stringify(updated));
  };

  const getStatusClass = (status) => {
    if (status === "Safe") return "status-safe";
    if (status === "Moderate") return "status-moderate";
    return "status-danger";
  };

  return (
    <div className="page-container">
      <div className="scanner-card fade-in">
        <h1>🔒 CyberWall File Scanner</h1>

        <div className="upload-section">
          <input type="file" onChange={handleFileChange} />
          <button onClick={handleUpload} className="scan-btn">
            Scan File
          </button>
        </div>

        {result && (
          <div className="result-card fade-in">
            <h3>Scan Result</h3>

            <p>
              <strong>Filename:</strong> {result.filename}
            </p>

            <p>
              <strong>Status:</strong>{" "}
              <span className={getStatusClass(result.status)}>
                {result.status}
              </span>
            </p>

            <p>
              <strong>Heuristic Score:</strong> {result.score}
            </p>

            <h4>Reasons:</h4>
            <ul>
              {result.reasons &&
                result.reasons.map((r, index) => <li key={index}>{r}</li>)}
            </ul>

            <h4>Extracted Features:</h4>
            <table className="feature-table">
              <tbody>
                {Object.entries(result.features).map(([key, value]) => (
                  <tr key={key}>
                    <td>
                      <strong>{key}</strong>
                    </td>
                    <td>{value.toString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* HISTORY SECTION */}
      <div className="history-card fade-in">
        <h2>📜 Scan History</h2>

        {history.length === 0 ? (
          <p>No scans yet.</p>
        ) : (
          <ul className="history-list">
            {history.map((item, index) => (
              <li key={index} className="history-entry">
                <span className="history-filename">{item.filename}</span>

                <span className={`history-status ${getStatusClass(item.status)}`}>
                  {item.status}
                </span>

                <span className="history-time">{item.time}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

export default App;
