import re

def detect_bank(text, metadata):
    text_lower = text.lower()
    meta = " ".join([str(v).lower() for v in metadata.values()])

    BANK_RULES = {
        "Capitec": {
            "keywords": ["capitec bank", "global one", "capitec statement"],
            "patterns": [r"branch: *47\\d{3}", r"capitec\\.co\\.za"],
            "metadata": ["capitec", "cpt statement", "global one"]
        },
        "FNB": {
            "keywords": ["first national bank", "fnb", "nav>>", "you can bank on us"],
            "patterns": [r"account +\\d{4} +branch +250655", r"fnb\\.co\\.za"],
            "metadata": ["fnb", "first national bank", "nav app"]
        },
        "Standard Bank": {
            "keywords": ["standard bank", "sbsa", "it can be", "standard bank statement"],
            "patterns": [r"branch: *051001", r"standardbank\\.co\\.za"],
            "metadata": ["standard bank", "sbsa", "stanbic"]
        },
        "ABSA": {
            "keywords": ["absa bank", "absa group", "your tomorrow starts today"],
            "patterns": [r"\\babsa\\b.*\\d{10}", r"\\babsa\\.co\\.za\\b"],
            "metadata": ["absa", "absa group limited"]
        },
        "Nedbank": {
            "keywords": ["nedbank", "money app", "see money differently"],
            "patterns": [r"branch +198765", r"nedbank\\.co\\.za"],
            "metadata": ["nedbank", "greenbacks"]
        },
        "Discovery Bank": {
            "keywords": ["discovery bank", "vitality money", "world’s first behavioural bank"],
            "patterns": [r"dbank\\d{6}", r"discovery\\.co\\.za"],
            "metadata": ["discovery bank", "vitality money"]
        },
        "TymeBank": {
            "keywords": ["tymebank", "everyday account", "go time", "tyme"],
            "patterns": [r"tyme\\d{6}", r"tymebank\\.co\\.za"],
            "metadata": ["tymebank"]
        },
        "African Bank": {
            "keywords": ["african bank", "real people real banking"],
            "patterns": [r"africanbank\\.co\\.za", r"\\bafb\\d{8}\\b"],
            "metadata": ["african bank"]
        }
    }

    for bank, rules in BANK_RULES.items():
        if any(k in text_lower for k in rules["keywords"]):
            return bank
        if any(m in meta for m in rules["metadata"]):
            return bank
        for pat in rules["patterns"]:
            if re.search(pat, text_lower):
                return bank

    return "Unknown"
