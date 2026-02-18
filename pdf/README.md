NEURO-SYMBOLIC AI FOR HYBRID ELECTRIC VEHICLE (HEV) CONTROL & SECURITY

ABSTRACT

This repository contains the source code for a Diploma Thesis implementing a novel Neuro-Symbolic Control System for Hybrid Electric Vehicles (HEVs). The system combines Deep Reinforcement Learning (PPO) for energy management with a Large Language Model (Llama 3) for semantic driver intent understanding. Furthermore, it integrates a CAN Bus Intrusion Detection System (IDS) to ensure vehicle cybersecurity.

KEY FEATURES AND INNOVATIONS

1. Prompt Engineering & Semantic Interface
The system utilizes advanced Prompt Engineering techniques to guide the Llama 3 model. Through carefully designed system prompts and role-playing constraints, the model translates natural language commands (including slang and metaphors) into deterministic engineering parameters. This ensures the output is always valid JSON, preventing hallucinations common in LLMs.

2. Software Engineering Standards (CI/CD & Typing)
The project adheres to production-grade software engineering practices. It includes a Continuous Integration and Continuous Deployment (CI/CD) pipeline to automate testing and validation. The codebase features strict Type-Hinting (demonstrated extensively in modules like can_bus_firewall.py) to ensure code reliability and easier maintenance.

3. Hybrid Control Strategy
It utilizes Proximal Policy Optimization (PPO) to optimize the trade-off between fuel consumption and battery usage, adapting to the driver's intent derived from the LLM.

4. Cybersecurity & Performance Monitoring
A Rule-based Intrusion Detection System (IDS) monitors CAN Bus traffic for anomalies such as DoS and Spoofing attacks. Additionally, a custom Profiling and Logging module records real-time system metrics, including CPU and RAM usage, ensuring the system remains efficient during execution.

PROJECT STRUCTURE

Core System:
main.py: The central CLI orchestrator.
app.py: The Web GUI built with Streamlit.
full_system.py: Connects the LLM intent analysis with the PPO Agent.
AI_agent.py: Contains the PPO Agent logic and custom Gym Environment.

Security & Safety:
can_bus_firewall.py: Implementation of the IDS with strict type hinting.
test_security.py: Unit tests for verifying firewall performance.

Evaluation & Utilities:
profiling.py: Captures CPU, RAM, and execution time metrics.
benchmark.py: Comparative study script.
run_ablation.py: Ablation studies.
optimize.py: Hyperparameter optimization (Grid Search).

INSTALLATION

Prerequisites:
Python 3.8 or higher, Ollama (for Llama 3), and optionally Docker.

Setup Steps:

1. Clone the repository:
   git clone https://github.com/yourusername/neuro-symbolic-hev-thesis](https://github.com/Mcleftis/AI-agent-llm-hybrid-control.git
   cd neuro-symbolic-hev-thesis

2. Install Python Dependencies:
   pip install -r requirements.txt

3. Setup LLM (Ollama):
   Ensure Ollama is running and pull the required model:
   ollama pull llama3

USAGE

To launch the graphical dashboard:
streamlit run app.py

To use the Command Line Interface (CLI):

Train the PPO Agent:
python main.py --mode train --steps 100000

Run Semantic Demo:
python main.py --mode demo --driver_mood "I am in a hurry"

Run Optimization:
python main.py --mode optimize

DOCKER SUPPORT

To build and run the system within an isolated container:
docker build -t hev-ai-system .
docker run -p 8501:8501 hev-ai-system

LICENSE

This project is part of a Diploma Thesis and is licensed for educational and research purposes.
