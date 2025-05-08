
import joblib
import subprocess
import os
import sys
import io

# ====== 🔧 Encoding Setup ======
def setup_encoding():
    """Ensure UTF-8 encoding throughout the application."""
    # Set system encoding
    os.environ["PYTHONIOENCODING"] = "utf-8"
    
    # Configure console encoding
    if sys.platform == "win32":
        os.system('chcp 65001 > nul')  # Windows UTF-8 code page
        
    # Reconfigure standard streams
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# ====== 📦 Model Loading and Prediction Utilities ======
def load_models(api_model_folder, opcode_model_folder):
    """Load vectorizers and models from provided paths."""
    try:
        api_tfidf = joblib.load(os.path.join(api_model_folder, "api_tfidf_vectorizer.joblib"))
        api_model = joblib.load(os.path.join(api_model_folder, "api_model.joblib"))

        opcode_tfidf = joblib.load(os.path.join(opcode_model_folder, "opc_tfidf_vectorizer.joblib"))
        opcode_model = joblib.load(os.path.join(opcode_model_folder, "opc_model.joblib"))

        return api_tfidf, api_model, opcode_tfidf, opcode_model
    except Exception as e:
        print(f"❌ Error loading models: {e}")
        sys.exit(1)

def weighted_predict(api_content: str, opcode_content: str, api_tfidf, api_model, opcode_tfidf, opcode_model) -> int:
    """
    Predict using both models with weighted voting.
    Returns: 0 for benign, 1 for ransomware
    """
    X_vec_api = api_tfidf.transform([api_content])
    X_vec_opc = opcode_tfidf.transform([opcode_content])

    pred_api = int(api_model.predict(X_vec_api)[0])
    pred_opc = int(opcode_model.predict(X_vec_opc)[0])

    weight_api = 0.6
    weight_opc = 0.4

    weighted_score = (pred_api * weight_api) + (pred_opc * weight_opc)

    print(f"🔍 API Model Prediction: {pred_api}, Opcode Model Prediction: {pred_opc}")
    print(f"⚖️ Weighted Score: {weighted_score}")

    return 1 if weighted_score > 0.5 else 0

# ====== 🧠 LLM Analysis Helpers ======
def analyze_ransomware_with_llm(asm_file_path):
    """Trigger the LLM analysis script on the .asm file with proper UTF-8 handling."""
    try:
        print(f"🔍 Starting LLM analysis for: {asm_file_path}")
        
        # Create UTF-8 environment
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        
        result = subprocess.run(
            ["python", "ransomware_llm_analyzer//analyze_ransomware_asm.py", asm_file_path],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            env=env,
            timeout=300  # 5 minute timeout
        )
        
        print("\n" + "="*40)
        print("🤖 LLM Analysis Output")
        print("="*40 + "\n")
        
        # Print outputs with error handling
        if result.stdout:
            print(result.stdout)
        else:
            print("No output from analysis script")
            
        if result.stderr:
            print("\n" + "="*40)
            print("⚠️ Analysis Warnings/Errors")
            print("="*40 + "\n")
            print(result.stderr)
            
        return result.returncode == 0
        
    except subprocess.TimeoutExpired:
        print("❌ LLM analysis timed out after 5 minutes")
        return False
    except Exception as e:
        print(f"❌ Error during LLM analysis: {str(e)}")
        return False

def get_asm_path_from_txt(txt_path, asm_base_dir):
    """Given a .txt path, build the corresponding .asm path."""
    filename = os.path.basename(txt_path)
    asm_filename = filename.replace(".txt", ".asm")
    asm_path = os.path.join(asm_base_dir, asm_filename)
    return asm_path

# ====== 🚀 Main Execution Flow ======
def main():
    setup_encoding()

    print("🚀 Welcome to the Ransomware Detection System!")
    print("="*50 + "\n")
    
    try:
        # Get user inputs
        api_model_folder = input("📂 Enter folder path for API Call Model: ").strip()
        opcode_model_folder = input("📂 Enter folder path for Opcode Model: ").strip()

        api_file_path = input("\n📄 Enter API Calls data file path (.txt): ").strip()
        opcode_file_path = input("📄 Enter Opcode data file path (.txt): ").strip()
        
        # Load models
        print("\n⏳ Loading machine learning models...")
        api_tfidf, api_model, opcode_tfidf, opcode_model = load_models(
            api_model_folder, opcode_model_folder
        )

        # Read input files
        print("\n📖 Reading input files...")
        try:
            with open(api_file_path, 'r', encoding='utf-8') as f_api:
                api_content = f_api.read()

            with open(opcode_file_path, 'r', encoding='utf-8') as f_opc:
                opcode_content = f_opc.read()
        except UnicodeDecodeError:
            print("⚠️ Retrying with fallback encoding...")
            with open(api_file_path, 'r', encoding='latin-1') as f_api:
                api_content = f_api.read()
            with open(opcode_file_path, 'r', encoding='latin-1') as f_opc:
                opcode_content = f_opc.read()

        # Predict
        print("\n🔮 Analyzing file...")
        label = weighted_predict(
            api_content, opcode_content, 
            api_tfidf, api_model, 
            opcode_tfidf, opcode_model
        )
        
        print("\n" + "="*50)
        print(f"🏷️ Final Prediction: {'🚨 RANSOMWARE' if label == 1 else '✅ BENIGN'}")
        print("="*50 + "\n")

        # Further Analysis if Ransomware
        if label == 1:
            print("🚨 Ransomware detected! Preparing for deep analysis...\n")
            asm_base_dir = input("📂 Enter base directory for ASM files: ").strip()
            asm_path_api = get_asm_path_from_txt(api_file_path, asm_base_dir)

            if os.path.exists(asm_path_api):
                print(f"✅ Found ASM file: {asm_path_api}")
                if not analyze_ransomware_with_llm(asm_path_api):
                    print("⚠️ LLM analysis completed with warnings")
            else:
                print(f"❌ ASM file not found at: {asm_path_api}")
        else:
            print("✅ No further action needed for benign files.")

    except KeyboardInterrupt:
        print("\n🛑 Operation cancelled by user")
    except Exception as e:
        print(f"\n❌ Unexpected error: {str(e)}")
    finally:
        print("\n" + "="*50)
        print("🛑 Detection process completed")
        print("="*50 + "\n")

if __name__ == "__main__":
    main()
