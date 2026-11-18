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

score = 0

print("\n========== RISK CALCULATION ==========")

if permissions["has_internet"] == 1:
    score += 5
    print("+5 Internet permission")

if permissions["has_read_sms"] == 1:
    score += 20
    print("+20 Read SMS permission")

if permissions["has_camera"] == 1:
    score += 10
    print("+10 Camera permission")

if permissions["has_record_audio"] == 1:
    score += 10
    print("+10 Microphone permission")

if permissions["has_access_fine_location"] == 1:
    score += 10
    print("+10 Location permission")

if permissions["has_read_contacts"] == 1:
    score += 15
    print("+15 Contacts permission")

if permissions["has_read_call_log"] == 1:
    score += 20
    print("+20 Call log permission")

if api["sms"] > 0:
    score += 20
    print("+20 SMS API usage")

if api["accessibility"] > 0:
    score += 20
    print("+20 Accessibility API usage")

if components["service_count"] > 0:
    score += 10
    print("+10 Background service")

if components["receiver_count"] > 0:
    score += 10
    print("+10 Broadcast receiver")

if network["ip_address_count"] > 0:
    score += 5
    print("+5 IP address found")

if network["url_count"] >= 3:
    score += 5
    print("+5 Multiple URLs found")


print("\nFinal Risk Score:", score, "/ 100")

print("\n========== RISK LEVEL ==========")

if score < 30:
    level = "LOW RISK"

elif score < 60:
    level = "MEDIUM RISK"

else:
    level = "HIGH RISK"

print("Risk Level:", level)

