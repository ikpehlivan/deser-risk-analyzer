\# Samples



This folder contains \*\*safe, non-malicious\*\* sample inputs and usage examples for the Deserialization Risk Analyzer.



⚠️ No exploit payloads are included in this repository.



---



\## Purpose



\- Demonstrate how the tool behaves with different input types

\- Provide reproducible test cases for development and CI

\- Help users understand what “format detection” means



---



\## What to Put Here



\### 1) Benign Base64 Examples

\- Random base64 strings

\- Encoded JSON blobs

\- Encoded text content



Example:

\- `sample\_random\_base64.txt`

\- `sample\_json\_base64.txt`



\### 2) Safe “Format Header” Demonstrations (Optional)

If you want to demonstrate Java native serialization detection \*\*without weaponization\*\*:



\- You can store a minimal byte sequence that starts with the Java stream header:

&nbsp; - `AC ED 00 05`

\- Keep it as a tiny \*\*header-only\*\* example and clearly label it.



Example:

\- `java\_magic\_header.bin` (contains only the header bytes, not a real object graph)



\*\*Important:\*\* Avoid adding real serialized objects or gadget-chain-like data.



---

Analyze raw string input

python deser\_analyzer.py --input "hello-world" --out report.json



\## Example Commands



\### Analyze a Base64 string

```bash

python deser\_analyzer.py --input "<BASE64\_STRING>" --base64 --out report.json

