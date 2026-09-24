from flask import Flask, render_template, redirect, url_for
from sklearn.ensemble import IsolationForest
from datetime import datetime
import random

app = Flask(__name__)


# =========================================================
# DEVICES
# =========================================================

devices = [
    {
        "id": 1,
        "name": "Computer Lab 1",
        "room": "Computer Lab",
        "baseline": 30,
        "activity": 30,
        "difference": 0,
        "anomaly_score": 20,
        "status": "Normal",
        "threat_type": "",
        "reason": "",
        "isolated": False,
        "history": [30, 31, 29, 30, 32, 30, 29, 31]
    },

    {
        "id": 2,
        "name": "Smart Board 1",
        "room": "Classroom",
        "baseline": 25,
        "activity": 25,
        "difference": 0,
        "anomaly_score": 20,
        "status": "Normal",
        "threat_type": "",
        "reason": "",
        "isolated": False,
        "history": [24, 25, 26, 25, 24, 25, 26, 25]
    },

    {
        "id": 3,
        "name": "Security Camera 1",
        "room": "Hallway",
        "baseline": 40,
        "activity": 40,
        "difference": 0,
        "anomaly_score": 20,
        "status": "Normal",
        "threat_type": "",
        "reason": "",
        "isolated": False,
        "history": [39, 40, 41, 40, 39, 40, 41, 40]
    },

    {
        "id": 4,
        "name": "Teacher Laptop",
        "room": "Teacher Office",
        "baseline": 20,
        "activity": 20,
        "difference": 0,
        "anomaly_score": 20,
        "status": "Normal",
        "threat_type": "",
        "reason": "",
        "isolated": False,
        "history": [19, 20, 21, 20, 19, 20, 21, 20]
    }
]


events = []


# =========================================================
# AI MODEL
# =========================================================

def create_model(baseline):

    data = []

    for _ in range(300):
        value = random.gauss(baseline, 5)
        data.append([value])

    model = IsolationForest(
        contamination=0.05,
        random_state=42
    )

    model.fit(data)

    return model


# =========================================================
# ANALYZE DEVICE
# =========================================================

def analyze_device(device):

    baseline = device["baseline"]
    activity = device["activity"]

    difference = abs(activity - baseline)

    model = create_model(baseline)

    prediction = model.predict([[activity]])

    device["difference"] = difference

    if prediction[0] == -1 or difference >= 45:

        device["status"] = "Suspicious"

        device["anomaly_score"] = min(
            100,
            70 + difference
        )

        if activity > baseline:

            device["threat_type"] = "Activity Spike"

            device["reason"] = (
                "Device activity is significantly "
                "higher than its learned normal baseline."
            )

        else:

            device["threat_type"] = "Unusual Activity"

            device["reason"] = (
                "Device activity is significantly "
                "lower than its learned normal baseline."
            )

    else:

        device["status"] = "Normal"

        device["anomaly_score"] = min(
            69,
            20 + difference
        )

        device["threat_type"] = ""

        device["reason"] = ""


# =========================================================
# SAVE HISTORY
# =========================================================

def save_history(device):

    device["history"].append(device["activity"])

    if len(device["history"]) > 12:
        device["history"] = device["history"][-12:]


# =========================================================
# PREPARE DISPLAY DATA
# =========================================================

def prepare_device(device):

    activity = device["activity"]

    if activity < 0:
        activity = 0

    if activity > 100:
        activity = 100

    history_heights = []

    for value in device["history"]:

        height = value

        if height < 5:
            height = 5

        if height > 100:
            height = 100

        history_heights.append(height)

    return {
        "id": device["id"],
        "name": device["name"],
        "room": device["room"],
        "baseline": device["baseline"],
        "activity": device["activity"],
        "activity_width": activity,
        "difference": device["difference"],
        "anomaly_score": device["anomaly_score"],
        "status": device["status"],
        "threat_type": device["threat_type"],
        "reason": device["reason"],
        "isolated": device["isolated"],
        "history": device["history"],
        "history_heights": history_heights
    }


# =========================================================
# ANALYTICS
# =========================================================

def get_analytics():

    total = len(devices)

    normal = 0
    suspicious = 0
    isolated = 0

    for device in devices:

        if device["status"] == "Normal":
            normal += 1

        elif device["status"] == "Suspicious":
            suspicious += 1

        elif device["status"] == "Isolated":
            isolated += 1

    scores = [
        device["anomaly_score"]
        for device in devices
    ]

    if scores:
        average_score = round(
            sum(scores) / len(scores)
        )
    else:
        average_score = 0

    if suspicious > 0:
        threat_level = "HIGH"

    elif len(events) > 0:
        threat_level = "MEDIUM"

    else:
        threat_level = "LOW"

    return {
        "total_devices": total,
        "normal_devices": normal,
        "suspicious_devices": suspicious,
        "isolated_devices": isolated,
        "total_events": len(events),
        "average_score": average_score,
        "threat_level": threat_level
    }


# =========================================================
# MAIN DASHBOARD
# =========================================================

@app.route("/")
def dashboard():

    for device in devices:

        if not device["isolated"]:

            if device["status"] == "Normal":

                variation = random.randint(-4, 4)

                device["activity"] = max(
                    0,
                    device["baseline"] + variation
                )

                analyze_device(device)

                save_history(device)

    display_devices = [
        prepare_device(device)
        for device in devices
    ]

    analytics = get_analytics()

    return render_template(
        "dashboard.html",
        devices=display_devices,
        analytics=analytics,
        events=events
    )


# =========================================================
# SIMULATE ATTACK
# =========================================================

@app.route("/simulate_attack")
def simulate_attack():

    available = [
        device
        for device in devices
        if not device["isolated"]
    ]

    if not available:
        return redirect(url_for("dashboard"))

    device = random.choice(available)

    device["activity"] = random.randint(90, 100)

    analyze_device(device)

    save_history(device)

    events.append({
        "time": datetime.now().strftime("%H:%M:%S"),
        "type": "attack",
        "message": (
            f"AURA detected abnormal activity "
            f"on {device['name']}."
        )
    })

    return redirect(url_for("dashboard"))


# =========================================================
# ISOLATE DEVICE
# =========================================================

@app.route("/isolate/<int:device_id>")
def isolate_device(device_id):

    for device in devices:

        if device["id"] == device_id:

            device["isolated"] = True
            device["status"] = "Isolated"

            events.append({
                "time": datetime.now().strftime("%H:%M:%S"),
                "type": "isolation",
                "message": (
                    f"{device['name']} was isolated "
                    f"from the simulated network."
                )
            })

            break

    return redirect(url_for("dashboard"))


# =========================================================
# RESET
# =========================================================

@app.route("/reset")
def reset():

    original_data = [
        (30, [30, 31, 29, 30, 32, 30, 29, 31]),
        (25, [24, 25, 26, 25, 24, 25, 26, 25]),
        (40, [39, 40, 41, 40, 39, 40, 41, 40]),
        (20, [19, 20, 21, 20, 19, 20, 21, 20])
    ]

    for index, device in enumerate(devices):

        baseline = original_data[index][0]
        history = original_data[index][1]

        device["baseline"] = baseline
        device["activity"] = baseline
        device["difference"] = 0
        device["anomaly_score"] = 20
        device["status"] = "Normal"
        device["threat_type"] = ""
        device["reason"] = ""
        device["isolated"] = False
        device["history"] = history.copy()

    events.clear()

    return redirect(url_for("dashboard"))


# =========================================================
# DEMO MODE
# =========================================================

@app.route("/demo/start")
def demo_start():

    return redirect(url_for("dashboard"))


@app.route("/demo/attack")
def demo_attack():

    device = devices[0]

    device["activity"] = 98

    analyze_device(device)

    save_history(device)

    events.append({
        "time": datetime.now().strftime("%H:%M:%S"),
        "type": "attack",
        "message": (
            "Simulated abnormal activity detected "
            "on Computer Lab 1."
        )
    })

    return redirect(url_for("dashboard"))


@app.route("/demo/isolate")
def demo_isolate():

    device = devices[0]

    device["isolated"] = True
    device["status"] = "Isolated"

    events.append({
        "time": datetime.now().strftime("%H:%M:%S"),
        "type": "isolation",
        "message": (
            "Computer Lab 1 was isolated "
            "from the simulated network."
        )
    })

    return redirect(url_for("dashboard"))


# =========================================================
# RUN
# =========================================================

if __name__ == "__main__":

    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )