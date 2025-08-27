import argparse, json, re, sys, pandas as pd

try:
    import spacy
    NLP = spacy.load("en_core_web_sm")
except:
    NLP = None

PHONE_RE = re.compile(r"\b\d{10}\b")
AADHAR_RE = re.compile(r"\b\d{12}\b")
PASSPORT_RE = re.compile(r"\b[A-Z]\d{7}\b")
UPI_RE = re.compile(r"\b[\w.\-]{2,}@[\w.\-]{2,}\b|\b\d{10}@\w+\b")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
ADDRESS_HINT_RE = re.compile(r"(street|road|lane|nagar|sector|pin|pincode|\d{6})", re.I)

def redact_phone(s): return re.sub(r"\d(?=\d{4})","X",s)
def redact_aadhar(s): return re.sub(r"\d(?=\d{4})","X",s)
def redact_passport(s): return s[0]+"XXXXXXX" if s else s
def redact_upi(s): return (s.split("@")[0][:2]+"XXX@"+s.split("@")[1]) if "@" in s else "XXXX@upi"
def redact_email(s): return (s.split("@")[0][:2]+"XXX@"+s.split("@")[1]) if "@" in s else "XXX@redacted"
def redact_name(s): return f"{s.split()[0][0]}XXX {s.split()[-1][0]}XXX" if len(s.split())>=2 else s[0]+"XXX"

def looks_like_full_name(s):
    if len([t for t in s.split() if re.search(r"[A-Za-z]{2,}",t)])>=2: return True
    if NLP: return any(ent.label_=="PERSON" and len(ent.text.split())>=2 for ent in NLP(s).ents)
    return False
def looks_like_address(s):
    if ADDRESS_HINT_RE.search(s): return True
    if NLP: return any(ent.label_ in ("GPE","LOC","FAC") for ent in NLP(s).ents)
    return False
def looks_like_ip(s):
    p=s.split("."); 
    return len(p)==4 and all(p[i].isdigit() and 0<=int(p[i])<=255 for i in range(4))

def analyze_record(data):
    red, stand=dict(data), False
    has_name=has_email=has_addr=has_devip=False
    for k,v in data.items():
        if not isinstance(v,str): continue
        if k.lower() in ("phone","contact") and PHONE_RE.search(v): red[k]=redact_phone(v); stand=True
        elif k.lower()=="aadhar" and AADHAR_RE.search(v): red[k]=redact_aadhar(v); stand=True
        elif k.lower()=="passport" and PASSPORT_RE.search(v): red[k]=redact_passport(v); stand=True
        elif k.lower()=="upi_id" and UPI_RE.search(v): red[k]=redact_upi(v); stand=True
        elif k.lower()=="email" and EMAIL_RE.match(v): has_email=True
        elif k.lower()=="name" and looks_like_full_name(v): has_name=True
        elif k.lower()=="address" and looks_like_address(v): has_addr=True
        elif k.lower()=="device_id" and v: has_devip=True
        elif k.lower()=="ip_address" and looks_like_ip(v): has_devip=True
    if sum([has_name,has_email,has_addr,has_devip])>=2:
        if has_name and "name" in data: red["name"]=redact_name(data["name"])
        if has_email and "email" in data: red["email"]=redact_email(data["email"])
        if has_addr and "address" in data: red["address"]="[REDACTED_ADDRESS]"
        if has_devip:
            if "device_id" in data: red["device_id"]="[REDACTED_DEVICE_ID]"
            if "ip_address" in data: red["ip_address"]="[REDACTED_IP]"
        return True,red
    return stand,red

def process_file(inp,out):
    df=pd.read_csv(inp,dtype=str); col=[c for c in df.columns if c.lower()=="data_json"][0]
    rows=[]
    for _,r in df.iterrows():
        rid=r.get("record_id") or _
        try: d=json.loads(r[col])
        except: 
            try: d=json.loads(r[col].replace("'",'"'))
            except: rows.append({"record_id":rid,"redacted_data_json":r[col],"is_pii":False}); continue
        pii,red=analyze_record(d)
        rows.append({"record_id":rid,"redacted_data_json":json.dumps(red),"is_pii":pii})
    pd.DataFrame(rows).to_csv(out,index=False)

def main():
    p=argparse.ArgumentParser(); p.add_argument("input_file"); a,_=p.parse_known_args()
    process_file(a.input_file,"redacted_output_sudarshan_rangappa.csv")

if __name__=="__main__": main()
