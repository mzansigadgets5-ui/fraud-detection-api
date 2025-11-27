import re
from datetime import datetime

def safe_lower(x):
    try: return str(x).lower()
    except: return ""

def detect_account_number(text, bank):
    patterns = {
        "Capitec": r"\b\d{10}\b",
        "FNB": r"\b\d{11}\b",
        "Standard Bank": r"\b\d{9}\b",
        "ABSA": r"\b\d{10}\b",
        "Nedbank": r"\b\d{10,11}\b",
        "Discovery Bank": r"\bdbank\d{6}\b",
        "TymeBank": r"\btyme\d{6}\b",
        "African Bank": r"\bafb\d{8}\b"
    }
    pat = patterns.get(bank, None)
    if not pat: return None
    match = re.search(pat, text, flags=re.IGNORECASE)
    return match.group(0) if match else None

def detect_pdf_editing(metadata):
    flags = []
    meta = safe_lower(" ".join([str(v) for v in metadata.values()]))

    edit_signals = [
        "microsoft word",
        "photoshop",
        "smallpdf",
        "pdfsam",
        "online2pdf",
        "ilovepdf",
        "scanned pdf",
        "converted"
    ]

    for signal in edit_signals:
        if signal in meta:
            flags.append({"code": "METADATA_EDITED", "severity": "high",
                          "message": f"PDF edited using: {signal}"})

    if "moddate" in metadata and "creationdate" in metadata:
        try:
            if metadata["/ModDate"] != metadata["/CreationDate"]:
                flags.append({"code": "MODDATE_MISMATCH", "severity": "medium",
                              "message": "ModDate differs from CreationDate — edited PDF"})
        except:
            pass

    return flags

def validate_layout(bank, text):
    rules = {
        "Capitec": ["global one", "capitec bank"],
        "FNB": ["nav", "first national bank", "you can bank on us"],
        "Standard Bank": ["it can be", "standard bank"],
        "ABSA": ["absa", "your tomorrow starts today"],
        "Nedbank": ["see money differently", "nedbank"],
        "Discovery Bank": ["vitality money", "discovery bank"],
        "TymeBank": ["tymebank", "go time"],
        "African Bank": ["african bank"]
    }

    if bank not in rules:
        return []

    mismatches = []
    if not any(k in text.lower() for k in rules[bank]):
        mismatches.append({
            "code": "LAYOUT_MISMATCH",
            "severity": "high",
            "message": f"Layout does not match expected pattern for {bank}"
        })

    return mismatches

def arithmetic_check(opening, closing, total_in, total_out):
    expected = opening + total_in - total_out
    diff = abs(expected - closing)
    if diff > 5:
        return [{
            "code": "BALANCE_INCONSISTENCY",
            "severity": "high",
            "message": f"Balance mismatch detected (difference {diff:.2f})"
        }]
    return []

def fraud_score_from_flags(flags):
    score = 0
    for f in flags:
        if f["severity"] == "critical": score += 40
        elif f["severity"] == "high": score += 25
        elif f["severity"] == "medium": score += 10
        elif f["severity"] == "low": score += 5
    return min(score, 100)

def analyze_document(text, metadata, bank, opening, closing, total_in, total_out):
    flags = []
    flags += detect_pdf_editing(metadata)
    flags += validate_layout(bank, text)
    flags += arithmetic_check(opening, closing, total_in, total_out)

    account_number = detect_account_number(text, bank)

    score = fraud_score_from_flags(flags)
    status = "rejected" if score >= 50 else "accepted"

    return {
        "status": status,
        "fraud_score": score,
        "fraud_code": "DOC_REJECTED_MODIFIED" if status == "rejected" else "DOC_ACCEPTED_VERIFIED",
        "bank": bank,
        "account_number": account_number,
        "flags": flags,
        "summary": f"Score: {score} | Status: {status} | Bank: {bank} | Account: {account_number}"
    }
