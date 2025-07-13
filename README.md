# SECUREGRID Dataset Sorting and Validation Script

## Overview
This repository contains the Python script used to process, extract, and validate the SECUREGRID dataset,
a synthetic dataset developed for prioritizing cybersecurity vulnerabilities in SCADA and ICS environments.

The methodology integrates multiple authoritative frameworks including:
- IEC 62443 (industrial security levels)
- NIST SP 800-161 (supply chain risk)
- IEEE reliability standards
- Microsoft STRIDE threat modeling
- MITRE ATT&CK for ICS (tactics, techniques, procedures)

## Repository Contents
- `securegrid_dataset_script.py`: Main Python script that:
  - Loads the SECUREGRID dataset
  - Extracts records by threat intelligence source
  - Validates schema against all 35 required variables
  - Calls FIRST.org’s EPSS API for exploitation probability
  - Performs Anderson-Darling & KS tests on CVSS distributions
- `SECUREGRID_Dataset_SAMPLE.csv`: Example dataset (10 rows) for reproducibility validation
- `requirements.txt`: Lists Python packages needed to run the script

## Usage
1. Clone the repository:
    ```
    git clone https://github.com/KRosseini/securegrid-validation.git
    cd securegrid-validation
    ```

2. Install Python dependencies (recommend using a virtual environment):
    ```
    pip install -r requirements.txt
    ```

3. Run the script:
    ```
    python securegrid_dataset_script.py
    ```

This will print dataset validation summaries, extraction results by source, and run statistical tests.

## Requirements
- Python 3.8 or higher
- pandas, numpy, requests, scipy

If running manually:

## Authoritative Data Sources
This script and dataset were developed using data and intelligence from the following publicly available, authoritative sources. These links allow future researchers to retrieve comparable raw inputs for independent dataset synthesis or validation.

- **MITRE ATT&CK for ICS**  
  ATT&CK matrices for industrial control systems (TTP mappings)  
  https://attack.mitre.org/matrices/ics/

- **CISA Known Exploited Vulnerabilities (KEV) Catalog**  
  Catalog of actively exploited vulnerabilities affecting all sectors  
  https://www.cisa.gov/known-exploited-vulnerabilities-catalog

- **FIRST.org Exploit Prediction Scoring System (EPSS) API**  
  API for retrieving probabilistic exploitability scores for CVEs  
  https://api.first.org/epss

- **ExploitDB**  
  Database of public exploit proof-of-concept code and CVE mappings  
  https://www.exploit-db.com/

- **Dragos OT Cybersecurity Year in Review**  
  Reports analyzing threat activity targeting operational technology  
  https://www.dragos.com/ot-cybersecurity-year-in-review/

- **Mandiant M-Trends**  
  Annual intelligence on advanced threat actor campaigns and vulnerabilities exploited  
  https://www.mandiant.com/resources/m-trends

## Citation
If using this script in academic work, please cite:

> Rosseini, K. (2024). *SECUREGRID Dataset Sorting and Validation Script* [Python code]. [https://github.com/KRosseini/securegrid-validation](https://github.com/RedQueen11-Katya/securegrid-validation)

## License
Provided for academic and research reproducibility under terms compatible with your institution’s guidelines. For any questions, please contact the repository owner.
