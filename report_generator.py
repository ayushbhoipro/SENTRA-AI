import json


with open("analysis.json") as file:
    data = json.load(file)


print("========== SECURITY REPORT ==========")

print("App Name:", data["app_name"])
print("Package:", data["package_name"])


print("\n========== FINDINGS ==========")


findings = []


if data["permissions"]["has_internet"]:
    findings.append(
        "Application requests INTERNET permission"
    )


if data["network"]["url_count"] > 0:
    findings.append(
        f"Application contains {data['network']['url_count']} URLs"
    )


if len(findings) == 0:
    print("No suspicious behaviour detected")

else:
    for item in findings:
        print("[!] " + item)


print("\n========== END REPORT ==========")