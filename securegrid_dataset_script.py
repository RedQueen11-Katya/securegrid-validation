# securegrid_dataset_script.py
# SECUREGRID Dataset Sorting and Validation Script
# Author: Katrina Rosseini (2024)

import pandas as pd
import numpy as np
import requests
from scipy.stats import anderson, kstest

# ---------------------------
# STEP 1: Load the dataset
# ---------------------------
# Adjust path as needed
dataset_path = "SECUREGRID_Dataset.csv"
df = pd.read_csv(dataset_path)
print("Dataset loaded. First few rows:")
print(df.head())

# ---------------------------
# STEP 2: Extract by intelligence source
# ---------------------------
def extract_by_source(df, source_col):
    return df[df[source_col].notnull()]

sources = ['Source_MITRE', 'Source_CISA', 'Source_ExploitDB', 'Source_FIRST', 'Source_Mandiant_Dragos']
extracted_data = {source: extract_by_source(df, source) for source in sources}

for src, data in extracted_data.items():
    print(f"\nRecords attributed to {src}: {len(data)}")

# ---------------------------
# STEP 3: Schema validation
# ---------------------------
expected_vars = [
    'CVE_ID', 'CVSS_Score', 'EPSS_Score', 'Exploitability_Score', 'Exploit_Success_Rate',
    'Device_Criticality', 'IIoT_Integration_Level', 'Legacy_System_Dependency',
    'System_Complexity', 'Access_Control_Level', 'Authentication_Requirements',
    'Patch_Testing_Impact', 'Operational_Technology_Impact', 'Cascade_Effect_Score',
    'Detection_Complexity', 'Mean_Time_Between_Failures', 'Recovery_Point_Objective',
    'Time_to_Patch_Release', 'Days_Until_First_Exploit', 'Patch_Implementation_Complexity',
    'Supply_Chain_Risk_Score', 'Attack_Surface_Expansion', 'Industrial_Protocol_Vulnerability',
    'Exploit_Code_Maturity', 'Remediation_Level', 'Report_Confidence',
    'Sector', 'Nation_State_Threat_Level', 'Threat_Actor_Attribution',
    'Historical_Exploit_Flag', 'Sampled_TTP', 'Operational_Impact', 'Vendor_Security_History',
    'Component_Distribution_Footprint'
]

missing = [col for col in expected_vars if col not in df.columns]
if missing:
    print("WARNING: Missing columns:", missing)
else:
    print("Schema validated: all expected columns present.")

# ---------------------------
# STEP 4: EPSS score example retrieval
# ---------------------------
# This shows how to call the FIRST.org EPSS API
# NOTE: Their public API does not require an API key but has usage limits

def get_epss_score(cve_id):
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    response = requests.get(url)
    data = response.json()
    if data.get('data'):
        return data['data'][0]['epss']
    return None

# Example for first 3 CVEs
print("\nFetching example EPSS scores:")
for cve in df['CVE_ID'].dropna().unique()[:3]:
    score = get_epss_score(cve)
    print(f"{cve}: EPSS Score = {score}")

# ---------------------------
# STEP 5: Statistical distribution validation
# ---------------------------
print("\nPerforming Anderson-Darling and KS tests on CVSS_Score...")

cvss_data = df['CVSS_Score'].dropna()
anderson_result = anderson(cvss_data)
print("Anderson-Darling test statistic:", anderson_result.statistic)

ks_stat, ks_p = kstest(cvss_data, 'norm', args=(np.mean(cvss_data), np.std(cvss_data)))
print(f"Kolmogorov-Smirnov test: stat={ks_stat:.4f}, p={ks_p:.4f}")

# ---------------------------
# Done
# ---------------------------
print("\nScript complete. SECUREGRID dataset validation pipeline executed.")
