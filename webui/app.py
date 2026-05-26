import time
import os
from flask import Flask, Response, render_template

app = Flask(__name__)
LOG_FILE = "aivpn_alert.log"

def generate_log_stream():
    # Ensure file exists
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, 'a', encoding="utf-8").close()

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        # Trong môi trường Demo, đọc từ đầu file để thấy lịch sử cũ
        # f.seek(0, os.SEEK_END) 
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1) # Check continuously for new lines
                continue
            
            import re
            
            # Remove ANSI color codes
            line = re.sub(r'\x1b\[[0-9;]*m', '', line)
            
            # Replace terminology
            line = line.replace("Bồi thẩm đoàn", "Lớp phán quyết")
            line = line.replace("[JURY_VERDICT]", "[TỘI DANH ĐỊNH DANH]")
            
            # Filtering logic - Filter out AI low-level complexities
            if any(keyword in line for keyword in ["[DISCRETIZER]", "[COLD_START]", "[PARSER]"]):
                continue
                
            # Only keep execution results
            if any(keyword in line for keyword in ["[EVIDENCE]", "[ALERT]", "[FIREWALL]", "[BLOCK]", "[WHITELIST]", "[TỘI DANH ĐỊNH DANH]", "Tội danh định danh", "IP Bị Kết Án", "Quy tắc áp dụng", "TIẾN HÀNH KHÓA KHẨN CẤP"]):
                yield f"data: {line.strip()}\n\n"

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/stream")
def stream():
    # Set headers for Server-Sent Events
    return Response(generate_log_stream(), mimetype="text/event-stream", headers={
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no"
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True)
