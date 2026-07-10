# Architectural Decisions Log (ADR)

This log records the key architectural choices, designs, and technical decisions made during the development of BugHawk.

---

## ADR 01: Split Frontend (Flask) and Backend (FastAPI) Services

* **Status:** Accepted (Prototype Implementation)
* **Context:** The application must present a user interface (dashboard, logs registry, profile updates, settings) and handle high-throughput machine learning inference pipelines (loading models, processing tensors, tokenizing text/images).
* **Decision:** We split the codebase into two distinct Python apps:
  * **Frontend:** Built with Flask, serving HTML templates, handling session security, database operations, and external API requests.
  * **Backend:** Built with FastAPI, hosting PyTorch model loaders, BitsAndBytes quantization settings, and custom transformers pipelines.
* **Consequences:** 
  * + Clear code boundaries: UI-centric packages are separate from heavy machine learning packages.
  * + Independent scalability: Web layers can run on CPU hosts, while ML layers run on GPU-enabled instances.
  * - Increased deployment complexity: Requires configuring ports and container networks.
  * - Data redundancy: User details are handled on the frontend, but must be synchronized if the backend requires authentication or audit history checks.

---

## ADR 02: Model Selections

* **Status:** Accepted (Qwen-Coder & DistilBERT)
* **Context:** The application needs a powerful LLM for code generation, security explanations, and patch suggestions, and a classifier to segregate queries.
* **Decision:** 
  * **Causal Coder LLM:** Selected `Qwen2.5-Coder-1.5B-Instruct` (or 3B counterpart). It balances performance, memory footprint (runs on consumer hardware), and supports vision (image prompts).
  * **Sequence Classifier:** Selected DistilBERT (`distilbert-base-uncased`) to class user intent between `debug` and `threat`.
* **Consequences:**
  * + Qwen Coder models show strong benchmark numbers for programming tasks.
  * + DistilBERT is lightweight, enabling fast classification checks.
  * - Running both models concurrently on single-GPU hardware requires careful memory management, resulting in the creation of the `ModelCache` Singleton.
  * - The DistilBERT intent classifier is currently compiled and trained, but is not active in the FastAPI request loop.

---

## ADR 03: BitsAndBytes 4-bit Quantization

* **Status:** Accepted
* **Context:** Loading standard Coder LLM weights in 16-bit float mode requires significant VRAM (often >6GB), which is unavailable on standard developer setups.
* **Decision:** Implement 4-bit quantization using `BitsAndBytesConfig` (loading parameters as NF4 double-quantized parameters in bfloat16 compute configurations) when CUDA is available.
* **Consequences:**
  * + Reduces LLM VRAM footprint to <2.5GB, allowing developers to run inference locally on standard GPUs.
  * - Slight degradation in generation quality and reasoning speed compared to full precision models.

---

## ADR 04: Local File-Based SQLite Database for Prototype

* **Status:** Accepted (Prototype Phase only)
* **Context:** We need to store profile configurations, user accounts, and historical repository analyses without adding database administration overhead.
* **Decision:** Use SQLite stored in the local `instance/` folder.
* **Consequences:**
  * + Zero-setup: No server configuration required, database files are read/written directly on disk.
  * - Poor scalability: SQLite lacks support for high concurrent write volumes, making it unsuitable for multi-worker containerized deployments.
  * - Future migration to PostgreSQL will be required when scaling the application.
