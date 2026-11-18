import json


# -----------------------------
# LOAD ANALYSIS
# -----------------------------

with open("analysis.json") as file:
    analysis = json.load(file)


score = 0
findings = []
behaviours = []


# -----------------------------
# PERMISSION RISK
# -----------------------------

permissions = analysis["permissions"]

apis = analysis["api_usage"]
network = analysis["network"]
components = analysis["components"]

permission_weights = {

    "has_read_sms": 20,
    "has_receive_sms": 20,
    "has_read_contacts": 10,
    "has_write_contacts": 10,
    "has_read_call_log": 15,

    "has_record_audio": 15,

    "has_camera": 5,

    "has_access_fine_location": 5,

    "has_internet": 3

}


for permission, weight in permission_weights.items():

    if permissions.get(permission, 0):

        score += weight

        findings.append({

         "severity":(
         "HIGH" if weight >=20
         else "MEDIUM" if weight >=10
         else "LOW"
         ),

            "issue": permission.replace(
                "has_",""
            ).replace("_"," ").title(),

            "reason":
            f"Application requests {permission.replace('has_','')} permission."

        })

# ==============================
# BEHAVIOUR CORRELATION ANALYSIS
# ==============================

# Network communication chain

if (
    permissions.get("has_internet",0)
    and apis.get("network",0) > 0
    and network.get("url_count",0) > 0
):

    score += 8

    behaviours.append({
        "name": "External Communication Behaviour",
        "risk": "MEDIUM",
        "description":
        "Application has internet permission, network APIs and external endpoints."
    })

    score += 8

    behaviours.append({
        "name": "External Communication Behaviour",
        "risk": "MEDIUM",
        "description":
        "Application has internet permission, network APIs and external endpoints."
    })


# Data theft pattern
if (
    permissions.get("has_read_sms",0)
    and permissions.get("has_read_contacts",0)
    and permissions.get("has_internet",0)
):

    score += 20

    behaviours.append({
        "name": "Possible Data Exfiltration",
        "risk": "HIGH",
        "description":
        "Sensitive data access combined with internet communication."
    })


# Surveillance behaviour
if (
    permissions.get("has_camera",0)
    and permissions.get("has_record_audio",0)
    and permissions.get("has_internet",0)
):

    score += 15

    behaviours.append({
        "name": "Surveillance Pattern",
        "risk": "HIGH",
        "description":
        "Camera and microphone access combined with external communication."
    })


# -----------------------------
# API BEHAVIOUR RISK
# -----------------------------



api_weights = {

    "sms":25,
    "microphone":20,
    "contacts":15,
    "accessibility":30,
    "location":10,
    "network":5

}


for api, count in apis.items():

    if count > 0:

        risk = api_weights.get(api,0)

        score += risk

        behaviours.append({

            "name":api.title()+" API Usage",

            "risk":
            "HIGH" if risk>=20 else "MEDIUM",

            "description":
            f"Detected {count} usage instances of {api} related APIs."

        })


# -----------------------------
# NETWORK ANALYSIS
# -----------------------------




if network["url_count"] > 5:

    score += 10

    findings.append({

        "severity":"MEDIUM",

        "issue":"Multiple Network Endpoints",

        "reason":
        "Application contains many external URLs."

    })


if network["ip_address_count"] > 0:

    score += 15

    findings.append({

        "severity":"HIGH",

        "issue":"Hardcoded IP Addresses",

        "reason":
        "Application contains direct IP communication indicators."

    })



# -----------------------------
# COMPONENT ANALYSIS
# -----------------------------




if components["service_count"] > 5:

    score += 5

    behaviours.append({

        "name":"Multiple Background Services",

        "risk":"MEDIUM",

        "description":
        "Application contains several background services."

    })


if components["receiver_count"] > 5:

    score += 5

    behaviours.append({

        "name":"Broadcast Receivers",

        "risk":"MEDIUM",

        "description":
        "Application registers multiple broadcast receivers."

    })


# -----------------------------
# BEHAVIOUR CORRELATION RULES
# -----------------------------


if (
    permissions.get("has_camera",0)
    and permissions.get("has_internet",0)
):

    score += 15

    behaviours.append({

        "name":"Camera Data Transmission Risk",

        "risk":"HIGH",

        "description":
        "Camera access combined with internet capability may allow external data transmission."

    })


if (
    permissions.get("has_record_audio",0)
    and permissions.get("has_internet",0)
):

    score += 20

    behaviours.append({

        "name":"Audio Exfiltration Risk",

        "risk":"HIGH",

        "description":
        "Microphone access combined with network access is suspicious."

    })


if (
    permissions.get("has_read_sms",0)
    and permissions.get("has_internet",0)
):

    score += 25

    behaviours.append({

        "name":"SMS Exfiltration Risk",

        "risk":"HIGH",

        "description":
        "SMS access with internet capability may expose messages."

    })

# Network communication chain

if (
    permissions.get("has_internet",0)
    and apis.get("network",0) > 0
    and network.get("url_count",0) > 0
):

    score += 8

    behaviours.append({
        "name": "External Communication Behaviour",
        "risk": "MEDIUM",
        "description":
        "Application has internet permission, network APIs and external endpoints."
    })


# -----------------------------
# NORMALIZE SCORE
# -----------------------------

score = min(score,100)



if score < 20:
    level="LOW RISK"

elif score < 50:
    level="MEDIUM RISK"

else:
    level="HIGH RISK"

# -----------------------------
# REMOVE DUPLICATE BEHAVIOURS
# -----------------------------

unique_behaviours = []

seen = set()

for behaviour in behaviours:
    key = behaviour["name"]

    if key not in seen:
        unique_behaviours.append(behaviour)
        seen.add(key)

behaviours = unique_behaviours

# -----------------------------
# SAVE REPORT
# -----------------------------


report = {

    "app_name":
    analysis["app_name"],

    "package_name":
    analysis["package_name"],

    "risk_score":
    score,

    "risk_level":
    level,

    "findings":
    findings,

    "behaviours":
    behaviours

}



with open(
    "security_report.json",
    "w"
) as file:

    json.dump(
        report,
        file,
        indent=4
    )


score = min(score,100)

print("========== RISK ENGINE 2.0 ==========")

print(
    f"Final Risk Score: {score}/100"
)

print(
    f"Risk Level: {level}"
)

print(
    "\nReport generated successfully."
)