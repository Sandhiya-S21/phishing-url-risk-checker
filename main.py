import sqlite3
import re
import ipaddress
from datetime import datetime
from urllib.parse import urlparse,unquote
DB_NAME="url_scans.db"
SUSPICIOUS_KEYWORDS={"login","verify","verification","password","sigin","secure","account","update","banking","wallet","free","claim","gift","prize","urgent"}
SHORTENERS={"bit.ly","tinyurl.com","t.co","is.gd","cutt.ly","shotrurl.at","ow.ly"}
def connect_db():
    connection=sqlite3.connect(DB_NAME)
    connection.execute("""CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY AUTOINCREMENT,url TEXT NOT NULL,risk_score INTEGER NOT NULL,risk_level TEXT NOT NULL,findings TEXT NOT NULL,scanned_at TEXT NOT NULL)""")
    connection.commit()
    return connection
def analyze_url(url):
    url=url.strip()
    if not url:
        raise ValueError("URL cannot be empty.")
    if any(ch.isspace() or ord(ch)<32 for ch in url):
        raise ValueError("URL must not contain spaces or control characters.")
    if len(url)>2048:
        raise ValueError("URL is too long(maximum 2048 characters).")
    parsed=urlparse(url)
    if parsed.scheme.lower() not in("http","https"):
        raise ValueError("URL must begin with http:// or https://.")
    if not parsed.hostname:
        raise ValueError("URL must contain a valid hostname.")
    try:
        hostname=parsed.hostname.encode("idna").decode("ascii").lower()
        _=parsed.port
    except(UnicodeError,ValueError):
        raise ValueError("The hostname or port is invalid.")
    if(hostname.startswith(".")or hostname.endswith(".")or any(not label or len(label)>63 for label in hostname.split("."))):
        raise ValueError("The hostname format is invalid.")
    score=0
    findings=[]
    def flag(points,message):
        nonlocal score
        score+=points
        findings.append(f"+{points}:{message}")
    if len(url)>100:
        flag(10,"Unusally long url")
    if len(url)>200:
        flag(10,"Very long url")
    if parsed.scheme.lower()=="http":
        flag(10,"Uses HTTP instead of HTTPS")
    if "@" in parsed.netloc:
        flag(25,"Contains @in the url authority")
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        flag(25,"Uses an IP address as the hostname")
    except ValueError:
        pass
    if len(hostname.split("."))>=5:
        flag(10,"Contains many hostname components")
    if hostname in SHORTENERS:
        flag(15,"Uses a known URL-shortening domain")
    decoded_url=unquote(url).lower()
    found_keywords=sorted(keyword for keyword in SUSPICIOUS_KEYWORDS if re.search(rf"(?<![a-z]){re.escape(keyword)}(?![a-z])",decoded_url))
    score=min(score,100)
    if score >=50:
        level="High Risk"
    if score >=25:
        level="Medium Risk"
    else:
        level="Low Risk"
    if not findings:
        findings.append("No configured suspicious patterns were detected.")
    return score,level,findings
def save_scan(url,score,level,findings):
    with connect_db() as connection:
        connection.execute("""INSERT INTO scans(url,risk_score,risk_level,findings,scanned_at) VALUES(?,?,?,?,?)""",(url,score,level,":".join(findings),datetime.now().astimezone().isoformat(timespec="seconds")))
def check_url():
    url=input("\n Enter a url (or type 'back, to return):").strip()
    if url.lower() =="back":
        return
    try:
        score,level,findings=analyze_url(url)
    except ValueError as error:
        print(f"\n Invalid URL:{error}")
        return
    print("\n"+"="*48)
    print("URL ANLAYSIS RESULT")
    print("="*48)
    print(f"URL :{url}")
    print(f"Risk Score:{score}/100")
    print(f"Risk Level:{level}")
    print(f"\nFindings:")
    for finding in findings:
        print(f" -{findings}")
    print("\n Note: This score is heuristics, not a safety guarantee.")
    try:
        save_scan(url,score,level,findings)
        print("Scan saved to database.")
    except sqlite3.Error as error:
        print(f"Database error:{error}")
def view_history():
    with connect_db() as connection:
        rows=connection.execute("""SELECT id,url,risk_score,risk_level,scanned_at FROM scans ORDER BY id DESC LIMIT 20""").fetchall()
        print("\n"+"="*75)
        print("RECENT SCAN HISTORY(latest 20)")
        print("="*75)
        if not rows:
            print("No scans found. Analyze a URL first.")
            return
        for scan_id,url,score,level,scanned_at in rows:
            print(f"\nID:{scan_id}|{level}({score}/100)")
            print(f"URL:{url}")
            print(f"Time:{scanned_at}")
def search_history():
    keyword=input("\nEnter a URL or keyword to search:").strip()
    if not keyword:
        print("search keyword cannot be empty.")
        return
    try:
        with connect_db() as connection:
            rows=connection.execute("""SELECT id,url,risk_score,risk_level,scanned_at FROM scans WHERE instr(lower(url),lower(?))>0 ORDER BY id DESC LIMIT 20""",(keyword,)).fetchall()
        if not rows:
            print("No matching scans found.")
            return
        print("\nMatching scans:")
        for scan_id,url,score,level,scanned_at in rows:
            print(f"\nID:{scan_id}|{level}({score}/100)")
            print(f"URL:{url}")
            print(f"Time:{scanned_at}")
    except sqlite3.Error as error:
        print(f"Database error{error}")
def main():
    with connect_db():
        pass
    while True:
        print("\n"+"="*42)
        print("      PHISHING URL RISK CHECKER")
        print("="*42)
        print("1.Analyze a URL")
        print("2.View recent scan history")
        print("3.Search scan history")
        print("4.Exit")
        choice=input("Enter your choice(1-4):").strip()
        if choice=="1":
            check_url()
        elif choice=="2":
            view_history()
        elif choice=="3":
            search_history()
        elif choice=="4":
            print("Thank you for using Phishing URL Risk Checker!")
            break
        else:
            print("Invalid choice! Please Enter 1,2,3,or 4.")
if __name__=="__main__":
    try:
        main()
    except (KeyboardInterrupt,EOFError):
        print("\nProgram closed.")
    






























    
                         
        
