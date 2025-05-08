import os
import requests
import sys
import google.generativeai as genai



def read_asm_file(filepath):
    if not filepath.endswith(".asm"):
        raise ValueError("The file must be an .asm file.")
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
        return file.read()

def clean_asm_code(code, max_lines=200):
    """Optional: Clean and trim the .asm code to avoid huge prompts."""
    lines = code.splitlines()
    lines = [line for line in lines if line.strip() and not line.strip().startswith(";")]
    return "\n".join(lines[:max_lines])  # Limit to first 200 lines (tweakable)

def build_prompt(asm_code):
    return f"""
You are an expert malware analyst. Analyze the following disassembled x86 code to determine if it's part of ransomware.

Your task:
1. If it's ransomware, identify malicious functions and behavior.
2. What are its Malicious Actions?
3. What are its Code Indicators?
4. What are its Mitigation Strategies?
5. Keep your tone professional and clear.

.asm Code:
{asm_code}

Return the result printing and using these tags:

⚠️ Malicious Actions:
🔍 Code Indicators:
🛡️ Mitigation Strategies:

"""

def send_to_gemini(prompt, model="gemini-1.5-pro"):
    try:
        # Configure the Gemini API (you'll need to set up your API key)
        genai.configure(api_key="AIzaSyDsTaIuILL0X3TLhdRmAnAqlNPEBM3hLj8")
        
        # Initialize the model
        model = genai.GenerativeModel(model)
        
        # Generate content
        response = model.generate_content(prompt)
        
        # Return the generated text
        return response.text
        
    except Exception as e:
        raise RuntimeError(f"Gemini error: {str(e)}")

# def send_to_ollama(prompt, model="codellama:7b-instruct"):
#     print("Send function")
#     response = requests.post("http://localhost:11434/api/generate", json={
#         "model": model,
#         "prompt": prompt,
#         "stream": False
#     })
#     #print(response.status_code)
#     print(response.json().get("response", ""))
#     if response.status_code == 200:
#         return response.json().get("response", "")
#     else:
#         raise RuntimeError(f"Ollama error {response.status_code}: {response.text}")

'''def main():
    asm_path = "M:\\Ransomware_Lab\\ransomware_analysis\\disassembly_results_x86\\2e8af1ad4bb1e9f1bfdd3a04bf28363bbcdb3653e6aa4864f61b09c050378d51.exe.asm"  # 📝 Change to your actual .asm file
    if not os.path.exists(asm_path):
        print(f"❌ File not found: {asm_path}")
        return
    
    print(f"[+] Reading {asm_path}")
    asm_code = read_asm_file(asm_path)
    cleaned_code = clean_asm_code(asm_code)

    prompt = build_prompt(cleaned_code)
    print("[+] Sending to LLM via Ollama...")
    response = send_to_ollama(prompt)
    
    print("\n====== 🧠 LLM Mitigation Analysis ======\n")
    print(response)'''


def main():
    if len(sys.argv) < 2:
        print("Usage: python analyze_ransomware_asm.py <asm_file_path>")
        sys.exit(1)

    asm_path = sys.argv[1]
    if not os.path.exists(asm_path):
        print(f"❌ File not found: {asm_path}")
        return
    
    print(f"[+] Reading {asm_path}")
    asm_code = read_asm_file(asm_path)
    cleaned_code = clean_asm_code(asm_code)

    prompt = build_prompt(cleaned_code)
    print("[+] Sending to LLM via Ollama...")
    response = send_to_gemini(prompt)
    # print("response:", response)
    # data = response.json()
    # print("data:", data)
    print("\n====== 🧠 LLM Mitigation Analysis ======\n")
    print(response)

if __name__ == "__main__":
    main()




'''
import os
import requests
import sys

def read_asm_file(filepath):
    if not filepath.endswith(".asm"):
        raise ValueError("The file must be an .asm file.")
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
        return file.read()

def clean_asm_code(code, max_lines=200):
    """Optional: Clean and trim the .asm code to avoid huge prompts."""
    lines = code.splitlines()
    lines = [line for line in lines if line.strip() and not line.strip().startswith(";")]
    return "\n".join(lines[:max_lines])  # Limit to first 200 lines (tweakable)

def build_prompt(asm_code):
    return f"""
You are an expert malware analyst. Analyze the following disassembled x86 code to determine if it's part of ransomware.

Your task:
1. Check if this code is malicious or suspicious.
2. If it's ransomware, identify malicious functions and behavior.
3. Suggest technical system-level mitigation strategies in bullet points.
4. Keep your tone professional and clear.

You are an expert malware analyst. Analyze the following disassembled x86 code to determine if it's part of ransomware.

Your task:
1. Check if this code is malicious or suspicious.
2. If it's ransomware, identify malicious functions and behavior.
3. Suggest technical system-level mitigation strategies in bullet points.
4. Keep your tone professional and clear.

.asm Code:
{asm_code}

Return the result printing and using these tags:

⚠️ Malicious Actions:
🔍 Code Indicators:
🛡️ Mitigation Strategies:

"""

def send_to_ollama(prompt, model="codellama:7b-instruct-q4_0"):
    #print("Send function")
    response = requests.post("http://localhost:11434/api/generate", json={
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "num_gpu": 1,
            "num_thread": 8
        }
    })
    #print(response.status_code)
    print(response.json().get("response", ""))
    if response.status_code == 200:
        return response.json().get("response", "")
    else:
        raise RuntimeError(f"Ollama error {response.status_code}: {response.text}")

''''''def main():
    asm_path = "M:\\Ransomware_Lab\\ransomware_analysis\\disassembly_results_x86\\2e8af1ad4bb1e9f1bfdd3a04bf28363bbcdb3653e6aa4864f61b09c050378d51.exe.asm"  # 📝 Change to your actual .asm file
    if not os.path.exists(asm_path):
        print(f"❌ File not found: {asm_path}")
        return
    
    print(f"[+] Reading {asm_path}")
    asm_code = read_asm_file(asm_path)
    cleaned_code = clean_asm_code(asm_code)

    prompt = build_prompt(cleaned_code)
    print("[+] Sending to LLM via Ollama...")
    response = send_to_ollama(prompt)
    
    print("\n====== 🧠 LLM Mitigation Analysis ======\n")
    print(response)''''''


def main():
    if len(sys.argv) < 2:
        print("Usage: python analyze_ransomware_asm.py <asm_file_path>")
        sys.exit(1)

    asm_path = sys.argv[1]
    if not os.path.exists(asm_path):
        print(f"❌ File not found: {asm_path}")
        return
    
    print(f"[+] Reading {asm_path}")
    asm_code = read_asm_file(asm_path)
    cleaned_code = clean_asm_code(asm_code)

    prompt = build_prompt(cleaned_code)
    print("[+] Sending to LLM via Ollama...")
    response = send_to_ollama(prompt)
    
    print("\n====== 🧠 LLM Mitigation Analysis ======\n")
    print(response)

if __name__ == "__main__":
    main()
'''



