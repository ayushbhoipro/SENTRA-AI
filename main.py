import os


print("========== ALOO PARATHA APK SECURITY SCANNER ==========")


print("\n[1] Running APK Analysis...")
os.system("python analyzer.py")


print("\n[2] Calculating Risk Score...")
os.system("python risk_engine.py")


print("\n[3] Generating Security Report...")
os.system("python report_generator.py")


print("\n[4] Generating AI Explanation...")
os.system("python ai_explainer.py")



print("\n========== SCAN COMPLETE ==========")