# 🚀 Qingming ZKP Engine

> **"Elegant Brutality in Cryptography."** > Pushing hardware to its absolute physical limits through extreme low-level memory control and algorithmic dimensionality reduction on consumer-grade GPUs.

## 1. What is Qingming ZKP Engine?

**Qingming ZKP Engine** is a low-level Zero-Knowledge Proof (ZKP) hardware acceleration engine built for extreme performance. Natively and heavily optimized for the AMD HIP architecture, it bypasses bloated traditional concurrency frameworks. Through rigorous **Zero-Copy memory passthrough** and **Zero-Inversions algorithm refactoring**, it compresses massive polynomial commitments and FRI folding computations to their physical limits.

This engine proves one thing: in the ZK space, true geeks do not need to rely on astronomical computing clusters to mask inefficient code.

---

## 2. Peak Performance & Commercial Significance

### 📊 Benchmark Data (Scale: 2^24 / 16.77 Million Leaf Nodes)
Real-world benchmark on a single **AMD Radeon RX 7900 XTX (24GB VRAM / 96MB Infinity Cache)**:
* **GPU NTT Latency:** `18.94 ms`
* **GPU L0 Merkle Latency:** `763.35 ms`
* **FRI Prove (End-to-End):** `2.56 s` (Single-core CPU algorithmic dimensionality reduction, achieving a 620% performance surge compared to conventional implementations)
* **FRI Verify:** `26.55 ms`

### 🌍 Commercial & Industry Impact
Currently, the Web3 and ZK-Rollup (L2) space is suffering from severe "compute anxiety." Companies instinctively throw massive capital at expensive enterprise-grade GPU clusters (like NVIDIA H100s) just to stack up Proving Time.

Qingming ZKP Engine **shatters this compute hegemony**:
1. **Cost Dimensionality Reduction**: We proved that by precisely squeezing the L3 cache (Infinity Cache) of an AMD consumer-grade GPU and refactoring algebraic geometry operations, a graphics card costing under $1,000 can achieve enterprise-grade ZK proof generation speeds.
2. **Architectural Domination**: Abandoning brute-force multithreading, we rely purely on low-level pointer lifecycle takeovers and mathematical topology optimization (reducing millions of O(N) modular exponentiations into O(1) scalar multiplications). This drastically lowers the hardware requirements for the Host CPU.
3. **Foundation for Decentralized Provers**: Extremely low hardware barriers combined with ultra-fast generation speeds provide industrial-grade underlying ammunition for a truly decentralized ZK compute network where individual nodes can participate.

---

## 3. Quick Start

Ensure your hardware environment supports AMD HIP and the system has the corresponding dependencies installed (e.g., `ldd Ubuntu GLIBC 2.39`).

### 3.1 Run Full Benchmark (All)
One-click comparison of CPU and GPU performance differences at extreme scales:
```bash
cargo run --release -- all
```
<img width="1233" height="1073" alt="all" src="https://github.com/user-attachments/assets/415cdc2c-47ba-45d1-8a17-b61e4e0ce975" />

### 3.2 Run Pure GPU Saturation Test (GPU)
Directly invoke the low-level `libqingming.so` to experience the extreme speed of a saturated 96MB Infinity Cache:
```bash
cargo run --release -- gpu
```
<img width="1245" height="518" alt="gpu" src="https://github.com/user-attachments/assets/42a653da-5665-4ebb-a720-b7424145672f" />

### 3.3 Run Pure CPU Baseline Test (CPU)
View the traditional baseline latency without GPU acceleration:
```bash
cargo run --release -- cpu
```
<img width="1236" height="535" alt="cpu" src="https://github.com/user-attachments/assets/0ab3ec8c-3937-4225-a765-82c0d1704046" />

---

## 4. Commercial Agreement & License (Qingming License)

This project adopts a customized, commercially-friendly dual-track license. By using this codebase, you agree to the following terms:

### 4.1 Attribution Requirement
Any individual or entity that uses, modifies, or integrates this code (including its compiled binaries and core algorithmic logic) into other projects **MUST explicitly credit the original author in a prominent location** (e.g., README, software startup screen, website footer):
> **Core Engine Author: Lord of Manifolds (流形之主) - Zhang Xiaolong**

### 4.2 Community Edition Free Commercial License
* For startups, independent developers, or enterprises with an **annual revenue of less than $10 million (USD)**, this Community Edition code is permitted for **free commercial use** (including integration into your L2, DApp, or Prover network).
* Enterprises exceeding this revenue threshold must contact the author for an enterprise commercial license.

### 4.3 Ultimate GPU Optimized Custom Edition (Enterprise & Customization)
The current 2.56 seconds (single-threaded Fold) is just a showcase for the Community Edition. We possess a much more hardcore **Full-Chain GPU Offload Custom Edition** (throwing the entire protocol layer into a HIP Kernel, targeting near-millisecond latency).
If you are a top-tier ZK-Rollup team, a hardware acceleration provider, or require extreme customization for specific curves and scales, please contact the author for the Pro version or commercial consulting:
📧 **Contact Email:** [zhangxiaolong950@gmail.com](mailto:zhangxiaolong950@gmail.com)

---
*Built with pure logic, math, and mechanical sympathy.*
