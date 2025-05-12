# 🔐 Static Ransomware Detection and Mitigation Using Machine Learning

This project presents a **machine learning-based framework** for detecting and mitigating ransomware threats through **static analysis** of Windows PE32 (x86) binaries. It uses API call sequences and opcode patterns to train a dual-model classifier and employs a large language model to generate **text-based defense strategies** from disassembled malicious files.

---

## 📁 Dataset

- **Ransomware Samples:** 440 PE32 executables collected from [Malware Bazaar](https://bazaar.abuse.ch/) via API.
- **Benign Samples:** 498 verified PE32 executables from open-source repositories.
- All samples were processed securely in an **isolated VirtualBox (Xubuntu)** environment with automated file validation and disassembly using `radare2`.

---

## 🧠 Feature Engineering

Features are extracted using:
- **API Call Sequences**
- **Opcode Patterns**
- **n-gram (1,2)** model for sequential context
- **TF-IDF Vectorization** to build sparse feature matrices

---

## 🏗️ Model Architecture

- **Classifier:** Random Forest
- **Weighted Ensemble:**
  - API Calls → 60%
  - Opcode Patterns → 40%
- **Threshold:** 0.5 for classification

Benchmarked against:
- Logistic Regression
- Multinomial Naive Bayes
- Linear SVC

Achieved an **F1-score of 95%** via stratified cross-validation.

---

## 🔄 Mitigation Workflow

For samples classified as ransomware:
1. Disassemble to `.asm` using `radare2`
2. Upload to LLM (via API)
3. **LLM generates text-based mitigation strategies** from static code (no code execution involved)

---

## 🚫 Limitations

- PE32 exclusive: No support yet for ELF, Mach-O, Android APKs
- Susceptible to opcode/API obfuscation
- Static-only detection; no behavioral/dynamic analysis

---

## 🔮 Future Work

- Integrate **dynamic analysis** and **sandbox monitoring**
- Improve **adversarial robustness**
- Expand dataset diversity
- Build a **real-time alerting pipeline** for enterprise environments

---

## ⚙️ Setup & Usage

1. Clone the repo  
   ```bash
   [git clone https://github.com/your-username/ransomware-detector.git
   cd ransomware-detector](https://github.com/Ramya-Sree-V/Ransomware-Detection-using-Machine-Learning.git)
