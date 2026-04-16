import flet as ft
import subprocess
import glob
import os
import json
import threading
import sys
import re

# Get all PCAPs from pcaps folder
def get_pcaps():
    pcap_files = []
    for directory in ["pcaps/Outputs", "pcaps/outputs_server"]:
        if os.path.exists(directory):
            for file in glob.glob(f"{directory}/*.pcap"):
                pcap_files.append(file)
    return sorted(pcap_files)

# Configuration mapping for test buttons
QUICK_TESTS = {
    "Normal Traffic": "pcaps/outputs_server/normal_traffic_server.pcap",
    "SYN Flood": "pcaps/outputs_server/ddos_syn_flood_server.pcap",
    "TLS Flood": "pcaps/outputs_server/ddos_tls_flood_server.pcap",
    "Slowloris": "pcaps/outputs_server/ddos_slowloris_tls_server.pcap"
}

def main(page: ft.Page):
    # UI Setup
    page.title = "🔒 Encrypted DDoS Detector Dashboard"
    page.theme_mode = ft.ThemeMode.DARK
    page.padding = 20
    page.window.width = 1300
    page.window.height = 850
    page.window.resizable = True
    
    # State variables
    process = None
    log_messages = []
    
    # Load Model Config
    top_features = []
    try:
        if os.path.exists("model_config_hybrid.json"):
            with open("model_config_hybrid.json", "r") as f:
                config = json.load(f)
                features = config.get("features", [])
                top_features = features[:10]
    except Exception:
        top_features = ["Could not load features"]
        
    def append_log(text, color=ft.colors.WHITE):
        log_messages.append(ft.Text(text, color=color, selectable=True, font_family="monospace", size=13))
        # Keep only the last 1000 lines to prevent UI lag
        if len(log_messages) > 1000:
            log_messages.pop(0)
        log_view.controls = log_messages.copy()
        page.update()
        log_view.scroll_to(offset=-1, duration=100) # scroll to bottom
        
    def parse_dashboard_stats(line):
        """
        Naive parsing of stats if the script outputs it. 
        Adjust regex or string matching based on what live_detector.py actually outputs.
        """
        try:
            if "Total parsed flows" in line or "Flows" in line:
                pass
        except Exception:
            pass

    def run_detector(cmd):
        nonlocal process
        try:
            # Update status
            status_indicator.value = "Status: Running"
            status_indicator.color = ft.colors.GREEN_400
            page.update()
            
            # Change python executable to current running one
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            
            for line in process.stdout:
                line = line.strip()
                if not line:
                    continue
                color = ft.colors.WHITE
                if "[ALERT]" in line or "DDoS" in line:
                    color = ft.colors.RED_400
                elif "[NORMAL]" in line or "Normal" in line:
                    color = ft.colors.GREEN_400
                elif "[WARNING]" in line:
                    color = ft.colors.YELLOW_400
                elif "Why flagged?" in line or line.startswith(" - "):
                    color = ft.colors.CYAN_400
                    
                append_log(line, color)
                parse_dashboard_stats(line)
                
            process.wait()
            status_indicator.value = "Status: Stopped"
            status_indicator.color = ft.colors.ORANGE_400
            page.update()
        except Exception as e:
            append_log(f"Error running detector: {str(e)}", ft.colors.RED_400)
            status_indicator.value = "Status: Error"
            status_indicator.color = ft.colors.RED_400
            page.update()

    def start_detection(e):
        if status_indicator.value == "Status: Running":
            append_log("Detection is already running.", ft.colors.YELLOW_400)
            return
            
        cmd = [sys.executable, "live_detector.py"]
        
        if mode_toggle.value == "PCAP Replay Mode":
            if not pcap_dropdown.value:
                append_log("Please select a PCAP file first.", ft.colors.YELLOW_400)
                return
            cmd.extend(["--pcap", pcap_dropdown.value])
        
        cmd.extend(["--threshold", str(round(threshold_slider.value, 2))])
        cmd.extend(["--min-packets", str(int(min_packets_slider.value))])
        cmd.extend(["--flow-timeout", str(int(flow_timeout_slider.value))])
        
        if no_block_checkbox.value:
            cmd.append("--no-block")
            
        if verbose_checkbox.value:
            cmd.append("--verbose")
            
        append_log(f"Starting command: {' '.join(cmd)}", ft.colors.CYAN_400)
        threading.Thread(target=run_detector, args=(cmd,), daemon=True).start()

    def stop_detection(e):
        nonlocal process
        if process:
            process.terminate()
            process = None
            append_log("Detector stopped by user.", ft.colors.YELLOW_400)
            status_indicator.value = "Status: Stopped"
            status_indicator.color = ft.colors.ORANGE_400
            page.update()

    def clear_log(e):
        log_messages.clear()
        log_view.controls.clear()
        page.update()
        
    def refresh_pcaps(e=None):
        options = [ft.dropdown.Option(p) for p in get_pcaps()]
        pcap_dropdown.options = options
        if options and not pcap_dropdown.value:
            pcap_dropdown.value = options[0].key
        page.update()
        
    def quick_test(test_name):
        mode_toggle.value = "PCAP Replay Mode"
        pcap_path = QUICK_TESTS.get(test_name)
        
        # Check if the file exists
        if not pcap_path or not os.path.exists(pcap_path):
            append_log(f"PCAP for '{test_name}' not found at {pcap_path}", ft.colors.RED_400)
            return
            
        pcap_dropdown.value = pcap_path
        page.update()
        start_detection(None)

    # UI Components
    status_indicator = ft.Text("Status: Ready", color=ft.colors.GREEN_400, weight=ft.FontWeight.BOLD)
    
    # Dashboard Counters
    flows_count = ft.Text("0", size=24, color=ft.colors.WHITE, weight=ft.FontWeight.BOLD)
    ddos_count = ft.Text("0", size=24, color=ft.colors.RED_400, weight=ft.FontWeight.BOLD)
    normal_count = ft.Text("0", size=24, color=ft.colors.GREEN_400, weight=ft.FontWeight.BOLD)
    blocked_count = ft.Text("0", size=24, color=ft.colors.ORANGE_400, weight=ft.FontWeight.BOLD)
    rate_count = ft.Text("0 flows/s", size=24, color=ft.colors.BLUE_400, weight=ft.FontWeight.BOLD)

    def stat_card(title, value_control):
        return ft.Container(
            content=ft.Column([ft.Text(title, size=12, color=ft.colors.GREY_400), value_control], alignment=ft.MainAxisAlignment.CENTER),
            padding=15,
            bgcolor=ft.colors.ON_INVERSE_SURFACE,
            border_radius=10,
            expand=1
        )
        
    dashboard_row = ft.Row([
        stat_card("Total Flows", flows_count),
        stat_card("DDoS Detected", ddos_count),
        stat_card("Normal Flows", normal_count),
        stat_card("Blocked IPs", blocked_count),
        stat_card("Current Rate", rate_count),
    ])

    mode_toggle = ft.RadioGroup(
        content=ft.Row([
            ft.Radio(value="PCAP Replay Mode", label="PCAP Replay Mode"),
            ft.Radio(value="Live Capture Mode", label="Live Capture Mode")
        ]),
        value="PCAP Replay Mode"
    )

    pcap_dropdown = ft.Dropdown(
        options=[],
        label="Select PCAP File",
        expand=True
    )

    refresh_pcap_btn = ft.ElevatedButton("Refresh", icon=ft.icons.REFRESH, on_click=refresh_pcaps)
    refresh_pcaps() # Initial population

    threshold_slider = ft.Slider(min=0.5, max=0.99, value=0.85, divisions=49, label="{value}")
    min_packets_slider = ft.Slider(min=1, max=5, value=2, divisions=4, label="{value}")
    flow_timeout_slider = ft.Slider(min=1, max=10, value=3, divisions=9, label="{value}")

    no_block_checkbox = ft.Checkbox(label="--no-block (Dry Run)", value=False)
    verbose_checkbox = ft.Checkbox(label="--verbose (Explainability)", value=True)

    start_btn = ft.ElevatedButton("▶ START Detection", on_click=start_detection, bgcolor=ft.colors.GREEN_800, color=ft.colors.WHITE, style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=5)))
    stop_btn = ft.ElevatedButton("⏹ STOP Detection", on_click=stop_detection, bgcolor=ft.colors.RED_800, color=ft.colors.WHITE, style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=5)))
    clear_log_btn = ft.OutlinedButton("Clear Log", on_click=clear_log)

    quick_test_row = ft.Row([
        ft.ElevatedButton("Test Normal Traffic", on_click=lambda e: quick_test("Normal Traffic"), bgcolor=ft.colors.BLUE_GREY_800),
        ft.ElevatedButton("Test SYN Flood", on_click=lambda e: quick_test("SYN Flood"), bgcolor=ft.colors.BLUE_GREY_800),
        ft.ElevatedButton("Test TLS Flood", on_click=lambda e: quick_test("TLS Flood"), bgcolor=ft.colors.BLUE_GREY_800),
        ft.ElevatedButton("Test Slowloris", on_click=lambda e: quick_test("Slowloris"), bgcolor=ft.colors.BLUE_GREY_800),
    ], wrap=True)

    log_view = ft.ListView(auto_scroll=False, expand=True, spacing=2)
    log_container = ft.Container(
        content=log_view,
        bgcolor=ft.colors.BLACK,
        padding=10,
        border_radius=5,
        border=ft.border.all(1, ft.colors.GREY_800),
        expand=True
    )

    feature_list = ft.Column([ft.Text("Top 10 Important Features:", weight=ft.FontWeight.BOLD, color=ft.colors.CYAN_200)] + 
                             [ft.Text(f"• {f}", size=12, color=ft.colors.WHITE70) for f in top_features])

    # Layout Assembly
    left_panel = ft.Container(
        content=ft.Column([
            ft.Text("Configuration", size=20, weight=ft.FontWeight.BOLD),
            mode_toggle,
            ft.Text(""),
            ft.Row([pcap_dropdown, refresh_pcap_btn]),
            ft.Text(""),
            ft.Text("Detection Threshold"), threshold_slider,
            ft.Text("Min Packets to Analyze"), min_packets_slider,
            ft.Text("Flow Timeout (s)"), flow_timeout_slider,
            ft.Row([no_block_checkbox, verbose_checkbox]),
            ft.Text(""),
            ft.Row([start_btn, stop_btn, clear_log_btn]),
            ft.Text(""),
            ft.Divider(),
            ft.Text("Quick Tests", weight=ft.FontWeight.BOLD),
            quick_test_row,
            ft.Text(""),
            ft.Divider(),
            feature_list
        ], scroll=ft.ScrollMode.ADAPTIVE),
        width=450,
        padding=15,
        border=ft.border.only(right=ft.border.BorderSide(1, ft.colors.GREY_800))
    )

    right_panel = ft.Column([
        ft.Row([
            ft.Text("Real-time Log", size=20, weight=ft.FontWeight.BOLD),
            ft.Container(expand=True),
            status_indicator
        ]),
        log_container
    ], expand=True, padding=ft.padding.only(left=10))

    page.add(
        ft.Column([
            dashboard_row,
            ft.Container(height=10),
            ft.Row([left_panel, right_panel], expand=True, vertical_alignment=ft.CrossAxisAlignment.START)
        ], expand=True)
    )

    # Initial explainability message
    append_log("UI Initialized. Ready to analyze PCAP files...", ft.colors.GREEN_400)

if __name__ == "__main__":
    ft.app(target=main)
