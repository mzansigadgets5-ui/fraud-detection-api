from pypdf import PdfReader
import hashlib, re
from datetime import datetime

SEVERITY_SCORES = {
    "low": 5,
    "medium": 15,
    "high": 30,
    "critical": 45,
}

def _add_flag(fraud, code, message, severity="low", score=None):
    if score is None:
        score = SEVERITY_SCORES.get(severity, 5)
    fraud["flags"].append({
        "code": code,
        "message": message,
        "severity": severity,
    })
    fraud["fraud_score"] += score

def detect_bank_advanced(text, metadata):
    text_lower = text.lower()
    meta_str = " ".join(str(v).lower() for v in metadata.values()) if metadata else ""

    BANK_RULES = {
        "Capitec": {
            "keywords": ["capitec bank", "global one"],
            "meta": ["capitec"],
        },
        "FNB": {
            "keywords": ["first national bank", "fnb", "how can we help you"],
            "meta": ["first national bank", "fnb"],
        },
        "Standard Bank": {
            "keywords": ["standard bank", "it can be"],
            "meta": ["standard bank", "sbsa"],
        },
        "ABSA": {
            "keywords": ["absa bank", "absa group"],
            "meta": ["absa"],
        },
        "Nedbank": {
            "keywords": ["nedbank", "see money differently"],
            "meta": ["nedbank"],
        },
        "Discovery Bank": {
            "keywords": ["discovery bank", "vitality money"],
            "meta": ["discovery bank"],
        },
        "TymeBank": {
            "keywords": ["tymebank", "go time"],
            "meta": ["tymebank"],
        },
        "African Bank": {
            "keywords": ["african bank", "real people real banking"],
            "meta": ["african bank"],
        },
    }

    for bank, rules in BANK_RULES.items():
        if any(k in text_lower for k in rules["keywords"]):
            return bank
        if any(m in meta_str for m in rules["meta"]):
            return bank

    return "Unknown"

def extract_account_number(text, bank):
    patterns = {
        "Capitec": r"\b\d{10}\b",
        "FNB": r"\b\d{11}\b",
        "Standard Bank": r"\b\d{9}\b",
        "ABSA": r"\b\d{10}\b",
        "Nedbank": r"\b\d{10,11}\b",
        "Discovery Bank": r"\bdbank\d{6}\b",
        "TymeBank": r"\btyme\d{6}\b",
        "African Bank": r"\bafb\d{8}\b",
    }
    pat = patterns.get(bank)
    if not pat:
        return None
    m = re.search(pat, text, flags=re.IGNORECASE)
    return m.group(0) if m else None

def analyze_pdf_advanced(pdf_path):
    reader = PdfReader(pdf_path)
    meta = reader.metadata or {}

    fraud = {
        "status": "valid",
        "fraud_score": 0,
        "severity": "low",
        "fraud_code": None,
        "flags": [],
        "summary": "",
        "bank": "Unknown",
        "account_holder": None,
        "account_number": None,
        "opening_balance": None,
        "closing_balance": None,
        "total_in": 0.0,
        "total_out": 0.0,
        "important_transactions": [],
        "calculated_closing": None,
        "balance_difference": None,
        "file_hash": None,
        "technical": {},
    }

    # --- 1) STRUCTURAL SIGNALS (trailer) ---
    trailer = reader.trailer or {}
    if "/Prev" in trailer:
        _add_flag(
            fraud,
            "DOC_TAMPERED_INCREMENTAL",
            "PDF shows incremental updates (Prev in trailer) — often indicates editing.",
            "medium",
        )
    if "/XRefStm" in trailer:
        _add_flag(
            fraud,
            "DOC_TAMPERED_XREF_STREAM",
            "Cross-reference stream present — may indicate heavy editing or rebuilding.",
            "low",
        )

    # --- 2) METADATA / EDITING TOOLS ---
    creator = str(meta.get("/Creator", "unknown"))
    producer = str(meta.get("/Producer", "unknown"))
    meta_str = f"{creator} {producer}".lower()
    edit_tools = [
        "ilovepdf",
        "sejda",
        "foxit",
        "wondershare",
        "online2pdf",
        "pdfescape",
        "illustrator",
        "photoshop",
        "word",
        "office",
        "libreoffice",
    ]
    for tool in edit_tools:
        if tool in meta_str:
            _add_flag(
                fraud,
                "DOC_EDITED_TOOL",
                f"PDF was processed with {tool.title()} (metadata).",
                "high",
            )

    # --- 3) /ID MISMATCH ---
    ids = trailer.get("/ID", [])
    if isinstance(ids, (list, tuple)) and len(ids) >= 2:
        id1 = str(ids[0])
        id2 = str(ids[1])
        if id1 != id2:
            _add_flag(
                fraud,
                "DOC_FORGED_ID_MISMATCH",
                "PDF /ID values differ — strong signal of editing.",
                "high",
            )

    # --- 4) DATE METADATA ---
    create_date = meta.get("/CreationDate")
    mod_date = meta.get("/ModDate")
    fraud["technical"]["creation_date_raw"] = str(create_date)
    fraud["technical"]["mod_date_raw"] = str(mod_date)
    if create_date and mod_date and create_date != mod_date:
        _add_flag(
            fraud,
            "DOC_META_MODIFIED",
            "Creation date and modification date differ — likely edited.",
            "medium",
        )

    # --- 5) TEXT EXTRACTION ---
    full_text = ""
    for p in reader.pages:
        try:
            full_text += p.extract_text() or ""
        except Exception:
            continue

    # --- 6) BANK DETECTION ---
    bank = detect_bank_advanced(full_text, meta)
    fraud["bank"] = bank

    # --- 7) ACCOUNT NUMBER ---
    acc = extract_account_number(full_text, bank)
    fraud["account_number"] = acc

    # --- 8) ACCOUNT HOLDER ---
    owner_match = re.search(
        r"(account (holder|name)\s*[:\-]\s*)(.+)", full_text, re.IGNORECASE
    )
    if owner_match:
        fraud["account_holder"] = owner_match.group(3).strip()

    # --- 9) OPENING / CLOSING BALANCE ---
    bal_match = re.search(
        r"opening balance[:\s]*([0-9.,\-]+).*?closing balance[:\s]*([0-9.,\-]+)",
        full_text,
        re.IGNORECASE | re.DOTALL,
    )
    if bal_match:
        try:
            opening = float(bal_match.group(1).replace(",", ""))
            closing = float(bal_match.group(2).replace(",", ""))
            fraud["opening_balance"] = opening
            fraud["closing_balance"] = closing
        except ValueError:
            opening = closing = None
    else:
        opening = closing = None

    # --- 10) TRANSACTIONS & ANOMALIES ---
    lines = [ln.strip() for ln in full_text.splitlines() if ln.strip()]
    transactions = []
    date_pattern = re.compile(
        r"\b(\d{1,2}\s+[A-Za-z]{3}\s+\d{4}|\d{4}-\d{2}-\d{2})\b"
    )
    for line in lines:
        m = re.search(r"(-?[0-9][0-9.,]*\.\d{2})", line)
        if not m:
            continue
        amt_str = m.group(1).replace(",", "")
        try:
            amount = float(amt_str)
        except ValueError:
            continue

        lower = line.lower()
        if any(k in lower for k in ["salary", "deposit", "credit", "cr "]):
            direction = "in"
        elif any(
            k in lower
            for k in ["debit", "withdrawal", "atm", "pos", "fee", "payment", " dr", " dr "]
        ):
            direction = "out"
        else:
            direction = "in" if amount > 0 else "out"

        date_match = date_pattern.search(line)
        tx_date = date_match.group(0) if date_match else None

        transactions.append(
            {
                "line": line,
                "amount": amount,
                "direction": direction,
                "date_raw": tx_date,
            }
        )

    total_in = sum(
        t["amount"] for t in transactions if t["direction"] == "in" and t["amount"] > 0
    )
    total_out = sum(
        abs(t["amount"]) for t in transactions if t["direction"] == "out"
    )
    fraud["total_in"] = round(total_in, 2)
    fraud["total_out"] = round(total_out, 2)

    # --- 11) IMPORTANT TRANSACTIONS (TOP 5) ---
    important = sorted(transactions, key=lambda t: abs(t["amount"]), reverse=True)[:5]
    fraud["important_transactions"] = [
        {
            "description": t["line"][:200],
            "amount": t["amount"],
            "direction": t["direction"],
        }
        for t in important
    ]

    # --- 12) BALANCE CONSISTENCY ---
    if opening is not None and closing is not None:
        expected = opening + total_in - total_out
        diff = abs(expected - closing)
        fraud["calculated_closing"] = round(expected, 2)
        fraud["balance_difference"] = round(diff, 2)
        if diff > 1.0:
            _add_flag(
                fraud,
                "DOC_FAKE_BALANCE_FLOW",
                "Balances do not reconcile with transactions.",
                "high",
            )

    # --- 13) DUPLICATE / PATTERNED TRANSACTIONS ---
    seen_keys = set()
    dup_count = 0
    for t in transactions:
        key = (t["date_raw"], round(t["amount"], 2), t["direction"])
        if key in seen_keys:
            dup_count += 1

    # --- 14) FUTURE-DATED TRANSACTIONS ---
    now = datetime.utcnow()
    future_count = 0
    for t in transactions:
        if not t["date_raw"]:
            continue
        try:
            if "-" in t["date_raw"]:
                dt = datetime.strptime(t["date_raw"], "%Y-%m-%d")
            else:
                dt = datetime.strptime(t["date_raw"], "%d %b %Y")
            if dt > now:
                future_count += 1
        except:
            continue
    if future_count > 0:
        _add_flag(
            fraud,
            "DOC_INVALID_DATES",
            "One or more transactions appear to be dated in the future.",
            "medium"
        )

    # --- 15) FILE HASH ---
    with open(pdf_path, "rb") as f:
        fraud["file_hash"] = hashlib.sha256(f.read()).hexdigest()

    # --- 16) FINAL CLASSIFICATION (ONLY VALID OR FRAUDULENT) ---
    score = fraud["fraud_score"]

    if score <= 20:
        fraud["status"] = "valid"
        fraud["severity"] = "low"
        fraud["fraud_code"] = "DOC_ORIGINAL_VERIFIED"
        fraud["summary"] = "Document verified as ORIGINAL. All integrity checks passed."
    else:
        fraud["status"] = "fraudulent"
        fraud["severity"] = "high"
        fraud["fraud_code"] = "DOC_FRAUDULENT_TAMPERED"
        fraud["flags"].append({
            "code": "REJECT_DOCUMENT",
            "message": "Strong evidence of tampering detected. PLEASE REJECT THIS DOCUMENT AND CANCEL THE APPLICATION.",
            "severity": "critical"
        })
        fraud["summary"] = "Document flagged as FRAUDULENT — reject immediately."

    # Final summary (NO account_holder)
    fraud["summary"] = (
        f"Score: {fraud['fraud_score']} | Status: {fraud['status']} | "
        f"Bank: {fraud['bank']} | In: {fraud['total_in']} | Out: {fraud['total_out']}"
    )

    return fraud

