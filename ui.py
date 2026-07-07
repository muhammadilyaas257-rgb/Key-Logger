import random
import tkinter as tk
from tkinter import ttk

from analyzer import SAMPLES, analyze_email, analyze_url


class InputPanel(ttk.LabelFrame):
    def __init__(self, parent, app):
        super().__init__(parent, text="Intake", padding=16)
        self.app = app

        self.current_mode = "url"
        self.url_var = tk.StringVar()
        self.email_var = tk.StringVar()

        tab_row = ttk.Frame(self)
        tab_row.pack(fill="x", pady=(0, 12))

        self.url_tab = ttk.Button(tab_row, text="URL Intake", command=lambda: self.app.switch_tab("url"))
        self.url_tab.pack(side="left", padx=(0, 8))
        self.email_tab = ttk.Button(tab_row, text="Email Intake", command=lambda: self.app.switch_tab("email"))
        self.email_tab.pack(side="left")

        self.url_frame = ttk.Frame(self)
        self.url_frame.pack(fill="both")

        ttk.Label(self.url_frame, text="Suspect URL").pack(anchor="w", pady=(0, 6))
        self.url_entry = ttk.Entry(self.url_frame, textvariable=self.url_var, width=80)
        self.url_entry.pack(fill="x")

        self.sample_row = ttk.Frame(self.url_frame)
        self.sample_row.pack(fill="x", pady=(8, 0))
        ttk.Button(self.sample_row, text="Load phishing sample", command=lambda: self.load_sample("url", 0)).pack(side="left", padx=(0, 8))
        ttk.Button(self.sample_row, text="Load clean sample", command=lambda: self.load_sample("url", 1)).pack(side="left")

        self.email_frame = ttk.Frame(self)
        self.email_frame.pack(fill="both")
        self.email_frame.pack_forget()

        ttk.Label(self.email_frame, text="Suspect Email").pack(anchor="w", pady=(0, 6))
        self.email_text = tk.Text(self.email_frame, height=12, wrap="word", font=("Segoe UI", 10))
        self.email_text.pack(fill="both")

        self.sample_row_email = ttk.Frame(self.email_frame)
        self.sample_row_email.pack(fill="x", pady=(8, 0))
        ttk.Button(self.sample_row_email, text="Load phishing sample", command=lambda: self.load_sample("email", 0)).pack(side="left", padx=(0, 8))
        ttk.Button(self.sample_row_email, text="Load clean sample", command=lambda: self.load_sample("email", 1)).pack(side="left")

        action_row = ttk.Frame(self)
        action_row.pack(fill="x", pady=(12, 0))
        ttk.Button(action_row, text="Run Analysis", command=self.app.run_analysis).pack(fill="x")

    def show_tab(self, mode: str):
        self.current_mode = mode
        if mode == "url":
            self.url_frame.pack(fill="both")
            self.email_frame.pack_forget()
            self.url_tab.state(["!disabled"])
            self.email_tab.state(["!disabled"])
        else:
            self.url_frame.pack_forget()
            self.email_frame.pack(fill="both")
            self.url_tab.state(["!disabled"])
            self.email_tab.state(["!disabled"])

    def load_sample(self, mode: str, index: int):
        sample = SAMPLES[mode][index]
        if mode == "url":
            self.url_var.set(sample)
        else:
            self.email_text.delete("1.0", "end")
            self.email_text.insert("1.0", sample)


class ResultsPanel(ttk.LabelFrame):
    def __init__(self, parent, app):
        super().__init__(parent, text="Results", padding=16)
        self.app = app

        self.score_var = tk.StringVar(value="0")
        self.verdict_var = tk.StringVar(value="Awaiting analysis")
        self.description_var = tk.StringVar(value="Run an assessment to see a verdict.")
        self.case_var = tk.StringVar(value="CASE #0000")

        header = ttk.Frame(self)
        header.pack(fill="x")
        ttk.Label(header, textvariable=self.case_var, font=("Segoe UI", 10, "bold")).pack(anchor="w")

        top = ttk.Frame(self)
        top.pack(fill="x", pady=(10, 12))

        self.canvas = tk.Canvas(top, width=140, height=140, bg="#0A0D12", highlightthickness=0)
        self.canvas.pack(side="left")
        self.canvas.create_oval(8, 8, 132, 132, outline="#232A36", width=10)

        text_block = ttk.Frame(top)
        text_block.pack(side="left", fill="x", expand=True, padx=(16, 0))
        ttk.Label(text_block, textvariable=self.verdict_var, font=("Segoe UI", 16, "bold")).pack(anchor="w")
        ttk.Label(text_block, textvariable=self.description_var, wraplength=500, justify="left").pack(anchor="w", pady=(6, 0))

        self.findings_frame = ttk.Frame(self)
        self.findings_frame.pack(fill="both", expand=True)

        self.placeholder = ttk.Label(self.findings_frame, text="No findings yet. Submit a sample URL or email to begin.")
        self.placeholder.pack(anchor="w", pady=8)

    def draw_gauge(self, score: int, color: str):
        self.canvas.delete("all")
        self.canvas.create_oval(8, 8, 132, 132, outline="#232A36", width=10)
        self.canvas.create_arc(8, 8, 132, 132, start=90, extent=360 * (score / 100), outline=color, width=10, style="arc")
        self.canvas.create_text(70, 70, text=str(score), fill=color, font=("Segoe UI", 24, "bold"))
        self.canvas.create_text(70, 94, text="RISK / 100", fill="#7D8896", font=("Segoe UI", 9))

    def show_result(self, result, case_no: int):
        self.case_var.set(f"CASE #{case_no:04d}")
        self.score_var.set(str(result.score))
        self.verdict_var.set(result.verdict)
        self.description_var.set(result.description)
        self.draw_gauge(result.score, result.color)

        for child in self.findings_frame.winfo_children():
            child.destroy()

        if not result.findings:
            self.placeholder = ttk.Label(self.findings_frame, text="No red flags found in this heuristic scan.")
            self.placeholder.pack(anchor="w", pady=8)
            return

        for finding in result.findings:
            row = ttk.Frame(self.findings_frame)
            row.pack(fill="x", pady=4)
            severity_text = finding.severity.upper()
            severity_color = {"high": "#F0524B", "med": "#E8A33D", "low": "#7D8896"}.get(finding.severity, "#7D8896")
            ttk.Label(row, text=severity_text, foreground=severity_color, font=("Segoe UI", 9, "bold")).pack(side="left", padx=(0, 8))
            ttk.Label(row, text=finding.text, wraplength=720, justify="left").pack(side="left", fill="x", expand=True)
            ttk.Label(row, text=f"+{finding.score}", foreground="#7D8896").pack(side="right")


class PhishingAnalysisApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Phishing Analysis Unit")
        self.geometry("1100x760")
        self.minsize(980, 680)
        self.configure(bg="#0A0D12")
        self.current_tab = "url"
        self.case_counter = random.randint(1, 40)
        self.build_ui()

    def build_ui(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure("TFrame", background="#0A0D12")
        style.configure("TLabelframe", background="#0A0D12", foreground="#E7EBF2")
        style.configure("TLabelframe.Label", background="#0A0D12", foreground="#E7EBF2")
        style.configure("TLabel", background="#0A0D12", foreground="#E7EBF2")
        style.configure("TButton", background="#181D26", foreground="#E7EBF2")

        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        header = ttk.Frame(self, padding=(20, 18, 20, 8))
        header.grid(row=0, column=0, sticky="ew")
        ttk.Label(header, text="Phishing Analysis Unit", font=("Segoe UI", 24, "bold")).pack(anchor="w")
        ttk.Label(header, text="Desktop Python version with separated input and results panels", foreground="#7D8896").pack(anchor="w", pady=(4, 0))

        content = ttk.Frame(self, padding=(16, 8, 16, 16))
        content.grid(row=1, column=0, sticky="nsew")
        content.columnconfigure(0, weight=1)
        content.columnconfigure(1, weight=1)
        content.rowconfigure(0, weight=1)

        self.input_panel = InputPanel(content, self)
        self.input_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 8))

        self.results_panel = ResultsPanel(content, self)
        self.results_panel.grid(row=0, column=1, sticky="nsew")

        self.switch_tab("url")

    def switch_tab(self, mode: str):
        self.current_tab = mode
        self.input_panel.show_tab(mode)

    def run_analysis(self):
        if self.current_tab == "url":
            text = self.input_panel.url_var.get().strip()
            result = analyze_url(text)
        else:
            text = self.input_panel.email_text.get("1.0", "end")
            result = analyze_email(text)

        self.case_counter += 1
        self.results_panel.show_result(result, self.case_counter)


def launch():
    app = PhishingAnalysisApp()
    app.mainloop()
