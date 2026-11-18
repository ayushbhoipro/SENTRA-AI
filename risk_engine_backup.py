import json

# Open the analysis results
with open("analysis.json", "r") as file:
    data = json.load(file)

print("Analysis loaded successfully!")

print("\nApp name:", data["app_name"])
print("Package:", data["package_name"])


permissions = data["permissions"]

print("\n========== PERMISSIONS ==========")

print("Internet:", permissions["has_internet"])
print("Camera:", permissions["has_camera"])
print("Read SMS:", permissions["has_read_sms"])
print("Location:", permissions["has_access_fine_location"])


components = data["components"]
api = data["api_usage"]
network = data["network"]

print("\n========== COMPONENTS ==========")

print("Activities:", components["activity_count"])
print("Services:", components["service_count"])
print("Receivers:", components["receiver_count"])
print("Providers:", components["provider_count"])


print("\n========== API USAGE ==========")

print("SMS:", api["sms"])
print("Camera:", api["camera"])
print("Microphone:", api["microphone"])
print("Location:", api["location"])
print("Contacts:", api["contacts"])
print("Network:", api["network"])
print("Accessibility:", api["accessibility"])


print("\n========== NETWORK ==========")

print("URLs:", network["url_count"])
print("IP addresses:", network["ip_address_count"])



print("\n========== RISK CALCULATION ==========")


score = 0
findings = []

behaviours = []

# Rule 1: Internet permission
if data["permissions"]["has_internet"]:

    score += 5

    findings.append({
        "severity": "LOW",
        "issue": "Internet permission requested",
        "reason": "Application can communicate with external servers"
    })


# Rule 2: SMS + Internet
if (
    data["permissions"]["has_read_sms"]
    and data["permissions"]["has_internet"]
):

    score += 25

    findings.append({
        "severity": "HIGH",
        "issue": "SMS access with Internet permission",
        "reason": "Could allow reading messages and sending data externally"
    })


# Rule 3: Location + Internet
if (
    data["permissions"]["has_access_fine_location"]
    and data["permissions"]["has_internet"]
):

    score += 20

    findings.append({
        "severity": "MEDIUM",
        "issue": "Location tracking capability",
        "reason": "Application can collect location data and communicate online"
    })


# Rule 4: Accessibility abuse
if data["api_usage"]["accessibility"] > 0:

    score += 30

    findings.append({
        "severity": "HIGH",
        "issue": "Accessibility API usage detected",
        "reason": "Accessibility services are commonly abused by spyware"
    })


# Rule 5: Background services
if data["components"]["service_count"] > 0:

    score += 10

    findings.append({
        "severity": "MEDIUM",
        "issue": "Background service detected",
        "reason": "Application can execute tasks in background"
    })


# Rule 6: Multiple URLs
if data["network"]["url_count"] > 2:

    score += 10

    findings.append({
        "severity": "LOW",
        "issue": "Multiple URLs found",
        "reason": "Application communicates with multiple endpoints"
    })


# Behaviour correlation analysis


if (
    data["permissions"]["has_internet"]
    and data["network"]["url_count"] > 0
):

    behaviours.append({
        "name": "External Communication",
        "risk": "LOW",
        "description":
        "Application can communicate with external servers"
    })


if (
    data["permissions"]["has_read_sms"]
    and data["permissions"]["has_internet"]
):

    behaviours.append({
        "name": "Possible Data Exfiltration",
        "risk": "HIGH",
        "description":
        "Application can read SMS and send data externally"
    })


if (
    data["api_usage"]["accessibility"] > 0
):

    behaviours.append({
        "name": "Accessibility Abuse Potential",
        "risk": "HIGH",
        "description":
        "Accessibility APIs can be abused for monitoring user actions"
    })

print("\nFinal Risk Score:", score, "/ 100")

print("\n========== RISK LEVEL ==========")

if score < 30:
    level = "LOW RISK"

elif score < 60:
    level = "MEDIUM RISK"

else:
    level = "HIGH RISK"

print("Risk Level:", level)

print("\n========== THREAT FINDINGS ==========")

for finding in findings:

    print("\n[" + finding["severity"] + "]")
    print("Issue:", finding["issue"])
    print("Reason:", finding["reason"])

print("\n========== BEHAVIOUR ANALYSIS ==========")

for behaviour in behaviours:

    print("\nBehaviour:",
          behaviour["name"])

    print("Risk:",
          behaviour["risk"])

    print("Description:",
          behaviour["description"])
    

report = {

    "app_name": data["app_name"],

    "package_name": data["package_name"],

    "risk_score": score,

    "risk_level": level,

    "findings": findings,

    "behaviours": behaviours,

    "summary_context": {

        "total_findings": len(findings),

        "total_behaviours": len(behaviours),

        "network_activity":
        data["network"]["url_count"] > 0

    }

}


with open("security_report.json","w") as file:

    json.dump(report,file,indent=4)


print("\nSecurity report saved!")

