<img width="1248" height="930" alt="112105_44_26" src="https://github.com/user-attachments/assets/e5ad3bce-edd7-476c-be3b-43d430c7fc9a" />

----------------
# qingming-zkp
## 📦 What is in this Repo?

* **`src/main.rs`**: The exact Rust harness used to generate the benchmark logs.
* **CPU Baseline**: A standard, single-threaded implementation of Radix-2 DIT NTT and Poseidon Merkle Tree construction for verification.
* **Verification Logic**: Full FRI verifier to ensure mathematical consistency.

## 🛑 What is NOT in this Repo?

The core **Qingming L0 Engine** (`libqingming.so`) and the underlying mathematical topology are **AIRGAPPED**. 
You cannot run the GPU benchmarks locally without the proprietary hardware-bound binary. 

**This repo serves as a "Truth Detector."** Clone it. Run the CPU baseline on your $50,000 dual-EPYC servers. Realize the magnitude of the 319x gap.

## 🛠️ Usage

Ensure you have Rust (Nightly preferred) installed.

```bash
# Clone the harness
git clone [https://github.com/uulong950/qingming-zkp](https://github.com/uulong950/qingming-zkp)
cd qingming-zkp-rs

# Run the CPU baseline to verify math and establish your local speed reference
cargo run --release
