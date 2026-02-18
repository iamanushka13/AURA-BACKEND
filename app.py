from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
CORS(app)
import random
import datetime
import time

app = Flask(__name__)

retry_tracker = {}
otp_store = {}
profile_store = {}
domain_tracker = {}
otp_attempts = {}
request_timestamps = []
escalated_cases = {}
audit_logs = []

blacklist_ids = ["AAAA123456", "BBBB654321"]


# HOME
@app.route("/")
def home():
    return render_template("index.html")

# STEP 1: PROFILE SUBMISSION → GENERATE OTP

@app.route("/submit_profile", methods=["POST"])
def submit_profile():
    data = request.json
    email = data.get("email")

    if not email:
        return jsonify({"error": "Email required"}), 400

    profile_store[email] = data

    # Generate OTP
    otp = str(random.randint(100000, 999999))
    otp_store[email] = otp

    # Track domain clustering
    domain = email.split("@")[-1].lower()
    domain_tracker[domain] = domain_tracker.get(domain, 0) + 1

    # Track velocity
    request_timestamps.append(time.time())

    print("Generated OTP for", email, ":", otp)

    return jsonify({
        "status": "otp_sent",
        "message": "OTP sent successfully"
    })


# STEP 2: OTP VERIFY → RUN AI RISK ENGINE

@app.route("/verify_otp", methods=["POST"])
def verify_otp():
    data = request.json
    email = data.get("email")
    otp = data.get("otp")

    otp_attempts[email] = otp_attempts.get(email, 0)

    # Wrong OTP
    if otp_store.get(email) != otp:
        otp_attempts[email] += 1
        return jsonify({
            "status": "failed",
            "message": "Invalid OTP",
            "attempts": otp_attempts[email]
        })

    # OTP Correct → Risk Evaluation
    user_data = profile_store.get(email, {})
    name = user_data.get("name", "").strip().lower()
    id_number = user_data.get("id_number", "").strip()
    country = user_data.get("country", "").strip().lower()

    risk_score = 0
    signals = []
    suspicious_flag = False

    # DOCUMENT VALIDATION

    if len(id_number) != 10:
        risk_score += 25
        signals.append("Invalid ID format")

    if id_number in blacklist_ids:
        risk_score += 60
        signals.append("Blacklisted ID detected")

    # AML SIMULATION

    if name in ["fraud", "blacklisted"]:
        risk_score += 50
        signals.append("Sanctions match")

    # EMAIL RISK

    if "tempmail" in email.lower() or "fake" in email.lower():
        risk_score += 20
        signals.append("Disposable email detected")

    # GEO RISK

    low_risk_countries = ["india", "usa", "uk"]
    if country not in low_risk_countries:
        risk_score += 25
        signals.append("High-risk geography")

    # DOMAIN CLUSTERING

    domain = email.split("@")[-1].lower()
    if domain_tracker.get(domain, 0) > 3:
        risk_score += 25
        suspicious_flag = True
        signals.append("Domain clustering detected")

    # OTP FAILURE PATTERN

    if otp_attempts.get(email, 0) > 3:
        risk_score += 30
        suspicious_flag = True
        signals.append("Multiple OTP failures")

    # VELOCITY CHECK

    current_time = time.time()
    recent_requests = [t for t in request_timestamps if current_time - t < 60]

    if len(recent_requests) > 5:
        risk_score += 30
        suspicious_flag = True
        signals.append("High onboarding velocity detected")

    # Cap risk score
    risk_score = min(risk_score, 100)
    trust_index = 100 - risk_score

    # RISK CATEGORY
    if risk_score <= 40:
        decision = "APPROVED"
        status = "activated"
        risk_category = "LOW"

    elif risk_score <= 70:
        decision = "EDD REQUIRED"
        status = "pending"
        risk_category = "MEDIUM"

        escalated_cases[email] = {
            "email": email,
            "risk_score": risk_score,
            "signals": signals,
            "timestamp": str(datetime.datetime.now()),
            "status": "Under Manual Review"
        }

    else:
        decision = "HIGH RISK - BLOCKED"
        status = "blocked"
        risk_category = "HIGH"

        escalated_cases[email] = {
            "email": email,
            "risk_score": risk_score,
            "signals": signals,
            "timestamp": str(datetime.datetime.now()),
            "status": "High Risk - Waiting Compliance Decision"
        }

    # AI EXPLANATION
    if signals:
        explanation = "Trust reduced due to: " + ", ".join(signals)
    else:
        explanation = "All verification checks passed successfully."

    confidence_score = max(50, 100 - (risk_score // 2))

    # AUDIT LOG STORAGE
    audit_entry = {
        "email": email,
        "timestamp": str(datetime.datetime.now()),
        "risk_score": risk_score,
        "trust_index": trust_index,
        "risk_category": risk_category,
        "decision": decision,
        "signals": signals
    }

    audit_logs.append(audit_entry)

    response = {
        "status": "success",
        "risk_score": risk_score,
        "trust_index": trust_index,
        "risk_category": risk_category,
        "confidence_score": confidence_score,
        "signals": signals,
        "decision": decision,
        "account_status": status,
        "explanation": explanation,
        "audit_log": audit_entry
    }

    if suspicious_flag:
        response["fraud_alert"] = "⚠️ Suspicious behavioral pattern detected"

    return jsonify(response)

# ADMIN: VIEW ESCALATED CASES

@app.route("/admin/cases", methods=["GET"])
def view_cases():
    return jsonify(escalated_cases)


# ADMIN: APPROVE / REJECT CASE

@app.route("/admin/decision", methods=["POST"])
def admin_decision():
    data = request.json
    email = data.get("email")
    action = data.get("action")

    if email in escalated_cases:
        escalated_cases[email]["status"] = action

        if action == "Approved":
            result_status = "activated"
        else:
            result_status = "blocked"

        return jsonify({
            "updated": True,
            "final_status": result_status
        })

    return jsonify({"updated": False}), 404


# ADMIN: VIEW AUDIT LOGS

@app.route("/admin/audit", methods=["GET"])
def view_audit():
    return jsonify(audit_logs)


# ADMIN: BASIC ANALYTICS

@app.route("/admin/analytics", methods=["GET"])
def analytics():
    total = len(audit_logs)
    approved = len([a for a in audit_logs if a["decision"] == "APPROVED"])
    medium = len([a for a in audit_logs if a["risk_category"] == "MEDIUM"])
    high = len([a for a in audit_logs if a["risk_category"] == "HIGH"])

    avg_risk = 0
    if total > 0:
        avg_risk = sum(a["risk_score"] for a in audit_logs) / total

    return jsonify({
        "total_applications": total,
        "approved": approved,
        "medium_risk": medium,
        "high_risk": high,
        "average_risk_score": round(avg_risk, 2)
    })


# RUN APP

if __name__ == "__main__":
    app.run(debug=True)
