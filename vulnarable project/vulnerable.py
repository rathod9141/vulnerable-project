import requests
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

def read_requirements(file_path):
    dependencies = []
    try:
        with open(file_path, "r") as file:
            for line in file:
                if "==" in line:
                    name, version = line.strip().split("==")
                    dependencies.append((name, version))
    except FileNotFoundError:
        messagebox.showerror("File Not Found", f"Could not open: {file_path}")
    return dependencies

def check_vulnerability(package_name, package_version):
    url = "https://api.osv.dev/v1/query"
    payload = {
        "package": {"name": package_name, "ecosystem": "PyPI"},
        "version": package_version
    }
    try:
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            return response.json().get("vulns", [])
        else:
            return []
    except requests.exceptions.RequestException as e:
        return [f"Error: {str(e)}"]

def select_file():
    file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if file_path:
        file_path_var.set(file_path)
        status_var.set("File selected. Ready to scan.")

def run_audit():
    file_path = file_path_var.get()
    if not file_path:
        messagebox.showwarning("No File", "Please select a file first.")
        return

    dependencies = read_requirements(file_path)
    results = []
    vulnerable_count = 0

    results.append("Dependency Security Audit Report\n")

    for name, version in dependencies:
        vulns = check_vulnerability(name, version)
        if vulns:
            vulnerable_count += 1
            results.append(f"{name}=={version} is VULNERABLE!")
            for vuln in vulns:
                results.append(f"   {vuln.get('id')} - {vuln.get('summary')}")
        else:
            results.append(f"{name}=={version} is SAFE.")

    results.append(f"\nTotal dependencies scanned: {len(dependencies)}")
    results.append(f"Total vulnerable dependencies: {vulnerable_count}")
    results.append("\nAudit Complete.")

    result_textbox.delete(1.0, tk.END)
    result_textbox.insert(tk.END, "\n".join(results))

    save_path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        title="Save Report As",
        filetypes=[("Text files", "*.txt")]
    )

    if save_path:
        try:
            with open(save_path, "w", encoding="utf-8") as f:
                output = result_textbox.get("1.0", tk.END).strip()
                f.write(output)
            status_var.set(f"Report saved to {save_path}")
            messagebox.showinfo("Success", f"Audit complete!\nReport saved to:\n{save_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save file: {e}")
    else:
        status_var.set("Scan complete, report not saved.")




root = tk.Tk()
root.title("Dependency Security Auditor")
root.geometry("800x600")
root.configure(bg="#f5f5f5")

file_path_var = tk.StringVar()
status_var = tk.StringVar()


tk.Label(root, text="Dependency Security Auditor", font=("Helvetica", 18, "bold"), bg="#f5f5f5", fg="#2c3e50").pack(pady=10)


frame_top = tk.Frame(root, bg="#f5f5f5")
frame_top.pack(pady=5)
tk.Button(frame_top, text="Select File", command=select_file, font=("Arial", 12)).pack(side=tk.LEFT, padx=10)
tk.Entry(frame_top, textvariable=file_path_var, width=60, font=("Arial", 11)).pack(side=tk.LEFT, padx=10)


tk.Button(root, text="Scan Now", command=run_audit, font=("Arial", 12), bg="#2ecc71", fg="white", width=20).pack(pady=10)


result_textbox = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=90, height=25, font=("Courier New", 10))
result_textbox.pack(padx=10, pady=10)


status_label = tk.Label(root, textvariable=status_var, relief=tk.SUNKEN, anchor="w", bg="#ecf0f1", font=("Arial", 10))
status_label.pack(fill=tk.X, side=tk.BOTTOM)


status_var.set("Waiting for file selection...")
root.mainloop()