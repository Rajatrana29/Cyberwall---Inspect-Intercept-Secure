import json
import sqlite3
from tqdm import tqdm

INPUT_FILE = "/home/rajat/cyberwall/data/train_features_0.jsonl"
DB_FILE = "/home/rajat/cyberwall/backend/database/step1.db"


def extract_section_stats(section_data):
    try:
        sections = section_data.get("sections", [])
        if not sections:
            return 0, 0, 0
        
        entropies = [s.get("entropy", 0) for s in sections]
        return len(sections), max(entropies), sum(entropies) / len(entropies)
    except:
        return 0, 0, 0


def create_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS file_features (
        sha256 TEXT PRIMARY KEY,
        label INTEGER,
        appeared TEXT,
        size INTEGER,
        vsize INTEGER,
        imports INTEGER,
        exports INTEGER,
        has_debug INTEGER,
        has_resources INTEGER,
        has_signature INTEGER,
        has_tls INTEGER,
        numstrings INTEGER,
        avg_string_length REAL,
        strings_entropy REAL,
        num_paths INTEGER,
        num_urls INTEGER,
        num_registry INTEGER,
        mz_header INTEGER,
        num_sections INTEGER,
        max_entropy REAL,
        avg_entropy REAL,
        timestamp INTEGER,
        machine TEXT,
        characteristics INTEGER
    );
    """)
    conn.commit()
    return conn


def process_file():
    conn = create_db()
    cursor = conn.cursor()

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        for line in tqdm(f, desc="Processing JSONL"):
            try:
                data = json.loads(line)
            except:
                continue

            sha = data.get("sha256")
            label = data.get("label")
            appeared = data.get("appeared")

            gen = data.get("general", {})
            strings = data.get("strings", {})
            header = data.get("header", {}).get("coff", {})
            section = data.get("section", {})

            num_sec, max_ent, avg_ent = extract_section_stats(section)

            cursor.execute("""
            INSERT OR IGNORE INTO file_features (
                sha256, label, appeared,
                size, vsize, imports, exports,
                has_debug, has_resources, has_signature, has_tls,
                numstrings, avg_string_length, strings_entropy,
                num_paths, num_urls, num_registry, mz_header,
                num_sections, max_entropy, avg_entropy,
                timestamp, machine, characteristics
            )
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);
            """,
            (
                sha,
                label,
                appeared,
                gen.get("size", 0),
                gen.get("vsize", 0),
                gen.get("imports", 0),
                gen.get("exports", 0),
                gen.get("has_debug", 0),
                gen.get("has_resources", 0),
                gen.get("has_signature", 0),
                gen.get("has_tls", 0),
                strings.get("numstrings", 0),
                strings.get("avlength", 0.0),
                strings.get("entropy", 0.0),
                strings.get("paths", 0),
                strings.get("urls", 0),
                strings.get("registry", 0),
                strings.get("MZ", 0),
                num_sec,
                max_ent,
                avg_ent,
                header.get("timestamp", 0),
                header.get("machine", "NA"),
                len(header.get("characteristics", []))
            ))

    conn.commit()
    conn.close()
    print("\n✅ Completed! Step-1 DB saved at:", DB_FILE)


if __name__ == "__main__":
    process_file()
