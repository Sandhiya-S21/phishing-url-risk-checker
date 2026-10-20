# phishing-url-risk-checker
Python and SQLite-based phishing URL risk checker that analyzes suspicious URL patterns, calculates a risk score, and stores scan history for review.

##Features:
1.URL Validation
2.Suspicious pattern detection
3.Risk score from 0 to 100
4.Low, Medium, and High Risk classifications
5.SQLite scan-history database   
6.Searchable scan history
7.Parameterized SQL queries
8.Input validation and error handling

##Technologies:
1.Python 3
2.SQLite
3.Regular expression
4.Python standard library

##Requirements:
1.Python 3.10 or later
2.No third-party packages required

##How to Run:
1.Download or clone this repository.
2.Open a teriminal in the project directory.
3.Run:"Python main.py"
4.Select an option from the menu.
5.Scan history is saved automatically to `url_scans.db`

##Risk Scoring:
The checker looks for configured patterns such as:
-Long URLs
-HTTP instead of HTTPS
-Ip-address hostnames
-The `@` characters in the URL authority
-Excessive hostname components or hyphens 
-Known URL-shortening domains
-Suspicious Keywords

Risk Levels:
- 0-24 :Low Risk
- 25-49:Medium Risk
- 50-100:High Risk
- 
##Limitations:
This is an educational, rule-based tool. It does not verify whether a website is genuinely malicious or false negatives. HTTP does not guarantee that a site is safe.
The tool does not visit or automatically open submitted URLs.

##Future Improvements:
-Add unit tests with pytest
-Build a web interface using flask
-Add domain reputation Checks through a trusted threat-intelligence API
-Exports scan history to CSV
-Add charts showing historical risk scores

















