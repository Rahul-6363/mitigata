# 🕸️ ChronoPath: Autonomous Kill Chain Analyzer

[![Stack](https://img.shields.io/badge/Stack-Python%20%7C%20DuckDB%20%7C%20NetworkX-success.svg)]()
[![LLM](https://img.shields.io/badge/GenAI-Groq%20(Llama_3)-orange.svg)]()
[![Target](https://img.shields.io/badge/Target-15GB_on_16GB_RAM-blue.svg)]()

## 🎯 The Hackathon Pitch (For the Judges)
**Problem:** Traditional SIEMs crash or run out of memory when analyzing 15GB of logs on a standard 16GB laptop because they try to load everything into RAM. 
**Solution:** ChronoPath decouples data storage from graph relationships. We use **DuckDB** for out-of-core processing (reading JSON directly from disk without loading it into RAM). This filters 15GB of noise down to a few megabytes of suspicious events. We then use **NetworkX** to map these events in-memory instantly, and the free **Groq API** (Llama 3) to write the final incident report in under 500ms.

---

## 🤖 INSTRUCTIONS FOR THE AI CODING AGENT
**Dear AI Agent:** I am participating in a hackathon to build a Kill Chain and Attack Path Analysis tool. Please read the architecture outline below. Your task is to generate the code for this project file-by-file based on this README. 

**CRITICAL REQUIREMENT:** In every Python file you generate, you MUST include extensive inline comments starting with `[JUDGE EXPLANATION]`. These comments must explain *why* the code is written this way, how it handles the 15GB memory constraint, and what specific hackathon requirement it fulfills. The human developer needs these comments to understand the system end-to-end and explain it to the judges.

### 📂 Directory Structure to Build
```text
chronopath/
│
├── requirements.txt        # Python dependencies
├── rules.yaml              # Config-based detection rules (Bonus B-4)
├── src/
│   ├── parser.py           # DuckDB engine: reads logs, applies MITRE tags
│   ├── graph_engine.py     # NetworkX engine: links events, predicts next steps
│   └── app.py              # Streamlit UI & Groq LLM integration
```

---

### 📄 File 1: `requirements.txt`
**What this does:** Installs the necessary lightweight Python packages.
* **Agent Task:** Generate this file including: `duckdb`, `networkx`, `streamlit`, `streamlit-agraph` (for graph visualization), `pyyaml`, and `groq`.

### 📄 File 2: `rules.yaml`
**What this does:** Satisfies the hackathon requirement to "Add a new detection rule by editing a config file, not code" (Bonus B-4).
* **Agent Task:** Create a YAML file containing 3 simulated detection rules (e.g., Brute Force, Credential Dumping, Lateral Movement). Each rule must have:
  - `name`
  - `mitre_technique` (e.g., T1110)
  - `kill_chain_stage` (e.g., Credential Access)
  - `sql_condition`: The SQL WHERE clause logic to find this in the logs (e.g., `event_id = 4624 AND status = 'failed'`).

### 📄 File 3: `src/parser.py`
**What this does:** This is the data cruncher. It reads the 15GB log file without crashing the computer and flags suspicious events based on `rules.yaml`.
* **Agent Task:** Write a Python script that:
  1. Loads `rules.yaml`.
  2. Uses DuckDB to connect to an in-memory or local database.
  3. Uses DuckDB's `read_json_auto()` function to query a dummy local file (`data/logs.json`). *Include a `[JUDGE EXPLANATION]` explaining that `read_json_auto` streams from disk, keeping RAM usage low.*
  4. Applies the SQL conditions from the YAML file to filter the logs.
  5. Saves the resulting filtered rows (with their new MITRE tags) into a DuckDB table named `suspicious_events`.

### 📄 File 4: `src/graph_engine.py`
**What this does:** Takes the small list of suspicious events and links them together to form an attack path, predicting where the attacker can go next.
* **Agent Task:** Write a Python script using `networkx` that:
  1. Queries the `suspicious_events` table from DuckDB.
  2. Creates a Directed Graph (`nx.DiGraph`).
  3. Iterates through the events, adding nodes for Users, Hosts, and IPs, and edges representing the actions (e.g., User logged into Host).
  4. Creates a function `get_attack_path()` to find the longest connected path.
  5. Creates a function `look_ahead(node)` using `nx.descendants()` to find all hosts the attacker can currently reach from a compromised node. *Include a `[JUDGE EXPLANATION]` explaining how graph theory makes lateral movement calculation O(1) instead of heavy SQL joins.*

### 📄 File 5: `src/app.py`
**What this does:** The user interface. It shows a timeline, the graph, and uses AI to write a plain-English report.
* **Agent Task:** Write a Streamlit application that:
  1. Has a sidebar to trigger the analysis pipeline (`parser.py` -> `graph_engine.py`).
  2. Visualizes the NetworkX graph using `streamlit-agraph`.
  3. Highlights the "Look Ahead" nodes in yellow and "Compromised" nodes in red.
  4. Takes the final graph path data, formats it into a text string, and sends it to the `Groq` API (using `os.environ["GROQ_API_KEY"]` and model `llama3-8b-8192` or `llama3-70b-8192`). 
  5. The prompt should be: *"You are a SOC Analyst. Summarize this MITRE-tagged attack path into a short, plain English incident report. Explain where it started and what they can reach next."* Display the response on the UI.

---

## 🚀 How to Run the Project (Once Code is Generated)

1. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
2. **Set your free Groq API Key:**
   ```bash
   # On Mac/Linux
   export GROQ_API_KEY="your_api_key_here"
   # On Windows (Command Prompt)
   set GROQ_API_KEY="your_api_key_here"
   ```
3. **Run the Dashboard:**
   ```bash
   streamlit run src/app.py
   ```