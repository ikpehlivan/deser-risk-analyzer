<p align="center">
<img src="assets/logo.png" width="220" alt="Deserialization Risk Analyzer Logo">

</p>



\# Deserialization Risk Analyzer (Java/.NET)



A lightweight CLI tool that performs **safe, non-exploitative** analysis of inputs to identify potential **unsafe deserialization** patterns (Java native serialization/.NET BinaryFormatter-like data) and produces structured security reports.



> This project is intentionally **defensive**: it does **not** generate exploit payloads.



---



\## Why This Project?



Unsafe deserialization is a recurring enterprise security issue that can lead to:

\- Remote Code Execution (RCE)

\- Authentication bypass

\- Privilege escalation (context-dependent)



This tool helps security engineers and pentesters quickly:

\- Detect suspicious serialization formats

\- Flag high-risk indicators

\- Produce consistent remediation notes



---



\## Features



\- **Format detection (heuristic)**

&nbsp; - Java native serialization stream header detection (`AC ED 00 05`)

&nbsp; - .NET BinaryFormatter-like indicator detection (heuristic markers)

\- **Rule-based indicator matching (YAML)\*\*

&nbsp; - Add new indicators without changing code

\- **Risk rating**

&nbsp; - `low/medium/high` (based on findings)

\- **Reports**

&nbsp; - JSON output for automation/evidence

&nbsp; - Clean terminal summary



---



\## Project Structure

deser-risk-analyzer/

&nbsp; deser\_analyzer.py

&nbsp; requirements.txt

&nbsp; rules/

&nbsp;   signatures.yml

&nbsp; samples/

&nbsp;   README.md

&nbsp; README.md



---

\## Installation

git clone https://github.com/ikpehlivan/deser-risk-analyzer.git

cd deser-risk-analyzer

pip install -r requirements.txt

Python 3.10+ recommended.



Usage

1\) Analyze raw input (string)

python deser\_analyzer.py --input "some-data" --out report.json

2\) Analyze Base64 input

python deser\_analyzer.py --input "<BASE64\_STRING>" --base64 --out report.json

3\) Use custom signatures (rules)

python deser\_analyzer.py --input "<BASE64\_STRING>" --base64 --signatures rules/signatures.yml

Output (Report Format)

The tool generates a JSON file containing:



Detected format

Risk rating

Findings (title, severity, evidence, recommendation)

Notes template for reporting



Example (shortened):



{

&nbsp; "format": "java\_serialization",

&nbsp; "risk": "high",

&nbsp; "findings": \[

&nbsp;   {

&nbsp;     "severity": "high",

&nbsp;     "title": "Java native deserialization data detected",

&nbsp;     "evidence": "Stream starts with AC ED 00 05",

&nbsp;     "recommendation": "Avoid native deserialization of untrusted data..."

&nbsp;   }

&nbsp; ]

}

Rules (signatures.yml)

You can extend detection by adding new indicators:



indicators:

&nbsp; - title: "Potential gadget-chain related marker"

&nbsp;   needle: "TemplatesImpl"

&nbsp;   severity: "high"

&nbsp;   recommendation: "Review type restrictions and eliminate unsafe deserialization."

needle is a plain string that will be searched in the decoded input bytes.



This is heuristic and should be validated in context.



Ethical Use

Use this tool only on:

Systems you own

Systems you are explicitly authorized to test



