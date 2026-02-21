from flask import Flask, render_template, request, jsonify, session
import json
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'summit-range-hipaa-2025'

HIPAA_CONTROLS = {
    "Administrative Safeguards (§164.308)": {
        "weight": 40,
        "controls": [
            {"id": "AS-1", "ref": "§164.308(a)(1)", "name": "Security Management Process", "required": "Required",
             "risk": "Critical", "description": "Implement policies and procedures to prevent, detect, contain, and correct security violations.",
             "remediation": "Establish a formal security management program with documented policies, risk analysis procedures, and sanctions policy."},
            {"id": "AS-2", "ref": "§164.308(a)(1)(ii)(A)", "name": "Risk Analysis", "required": "Required",
             "risk": "Critical", "description": "Conduct an accurate and thorough assessment of potential risks and vulnerabilities to ePHI.",
             "remediation": "Perform documented risk analysis covering all ePHI systems. Update at least annually or after significant changes."},
            {"id": "AS-3", "ref": "§164.308(a)(1)(ii)(B)", "name": "Risk Management", "required": "Required",
             "risk": "Critical", "description": "Implement security measures sufficient to reduce risks and vulnerabilities to a reasonable and appropriate level.",
             "remediation": "Develop and implement a risk management plan with prioritized remediation actions and tracking."},
            {"id": "AS-4", "ref": "§164.308(a)(1)(ii)(C)", "name": "Sanction Policy", "required": "Required",
             "risk": "High", "description": "Apply appropriate sanctions against workforce members who fail to comply with security policies.",
             "remediation": "Document sanctions policy with graduated disciplinary actions. Train workforce on consequences of violations."},
            {"id": "AS-5", "ref": "§164.308(a)(1)(ii)(D)", "name": "Information System Activity Review", "required": "Required",
             "risk": "High", "description": "Implement procedures to regularly review records of information system activity.",
             "remediation": "Implement log monitoring and review procedures. Use SIEM tools for automated alerting on suspicious activity."},
            {"id": "AS-6", "ref": "§164.308(a)(2)", "name": "Assigned Security Responsibility", "required": "Required",
             "risk": "High", "description": "Identify the security official responsible for developing and implementing security policies.",
             "remediation": "Formally designate a HIPAA Security Officer in writing. Document roles and responsibilities."},
            {"id": "AS-7", "ref": "§164.308(a)(3)", "name": "Workforce Security", "required": "Required",
             "risk": "High", "description": "Implement policies for authorization, supervision, and termination of workforce access.",
             "remediation": "Create workforce access management procedures including onboarding, role changes, and termination checklists."},
            {"id": "AS-8", "ref": "§164.308(a)(4)", "name": "Information Access Management", "required": "Required",
             "risk": "Critical", "description": "Implement policies for authorizing access to ePHI based on minimum necessary standard.",
             "remediation": "Implement role-based access control (RBAC). Document access authorization procedures and review quarterly."},
            {"id": "AS-9", "ref": "§164.308(a)(5)", "name": "Security Awareness and Training", "required": "Required",
             "risk": "High", "description": "Implement a security awareness and training program for all workforce members.",
             "remediation": "Deploy annual HIPAA security training for all staff. Document completion records. Include phishing simulations."},
            {"id": "AS-10", "ref": "§164.308(a)(6)", "name": "Security Incident Procedures", "required": "Required",
             "risk": "Critical", "description": "Implement policies to address security incidents including identification and response.",
             "remediation": "Develop incident response plan with defined roles, escalation paths, and breach notification procedures."},
            {"id": "AS-11", "ref": "§164.308(a)(7)", "name": "Contingency Plan", "required": "Required",
             "risk": "High", "description": "Establish policies for responding to emergencies that damage systems containing ePHI.",
             "remediation": "Create and test data backup, disaster recovery, and emergency mode operation plans annually."},
            {"id": "AS-12", "ref": "§164.308(a)(8)", "name": "Evaluation", "required": "Required",
             "risk": "Medium", "description": "Perform periodic technical and non-technical evaluation of security policies.",
             "remediation": "Conduct annual HIPAA security evaluation. Document findings and track remediation progress."},
            {"id": "AS-13", "ref": "§164.308(b)(1)", "name": "Business Associate Contracts", "required": "Required",
             "risk": "Critical", "description": "Obtain satisfactory assurances from business associates that they will appropriately safeguard ePHI.",
             "remediation": "Execute BAAs with all vendors handling ePHI. Maintain a BA inventory and review agreements annually."},
        ]
    },
    "Physical Safeguards (§164.310)": {
        "weight": 20,
        "controls": [
            {"id": "PS-1", "ref": "§164.310(a)(1)", "name": "Facility Access Controls", "required": "Required",
             "risk": "High", "description": "Implement policies to limit physical access to electronic information systems and facilities.",
             "remediation": "Install access control systems (key cards, PINs). Maintain visitor logs. Restrict server room access."},
            {"id": "PS-2", "ref": "§164.310(b)", "name": "Workstation Use", "required": "Required",
             "risk": "Medium", "description": "Implement policies for proper use of workstations that access ePHI.",
             "remediation": "Document workstation use policies. Enforce screen locks, privacy screens in public areas, clean desk policy."},
            {"id": "PS-3", "ref": "§164.310(c)", "name": "Workstation Security", "required": "Required",
             "risk": "High", "description": "Implement physical safeguards for workstations that access ePHI.",
             "remediation": "Deploy cable locks, position screens away from public view. Restrict USB ports where possible."},
            {"id": "PS-4", "ref": "§164.310(d)(1)", "name": "Device and Media Controls", "required": "Required",
             "risk": "High", "description": "Implement policies for disposal and re-use of electronic media containing ePHI.",
             "remediation": "Implement NIST 800-88 media sanitization. Track all devices with ePHI. Use encrypted drives."},
        ]
    },
    "Technical Safeguards (§164.312)": {
        "weight": 30,
        "controls": [
            {"id": "TS-1", "ref": "§164.312(a)(1)", "name": "Access Control", "required": "Required",
             "risk": "Critical", "description": "Implement technical policies to allow only authorized persons to access ePHI.",
             "remediation": "Implement unique user IDs, MFA, automatic logoff, and encryption/decryption controls."},
            {"id": "TS-2", "ref": "§164.312(a)(2)(i)", "name": "Unique User Identification", "required": "Required",
             "risk": "Critical", "description": "Assign a unique name/number for identifying and tracking user identity.",
             "remediation": "Eliminate shared accounts. Assign unique IDs to every user. Implement identity management system."},
            {"id": "TS-3", "ref": "§164.312(a)(2)(ii)", "name": "Emergency Access Procedure", "required": "Required",
             "risk": "High", "description": "Establish procedures for obtaining necessary ePHI during an emergency.",
             "remediation": "Document and test emergency access procedures. Store break-glass credentials securely."},
            {"id": "TS-4", "ref": "§164.312(a)(2)(iii)", "name": "Automatic Logoff", "required": "Addressable",
             "risk": "Medium", "description": "Implement electronic procedures that terminate sessions after inactivity.",
             "remediation": "Configure automatic screen lock after 15 minutes of inactivity on all workstations and mobile devices."},
            {"id": "TS-5", "ref": "§164.312(a)(2)(iv)", "name": "Encryption and Decryption", "required": "Addressable",
             "risk": "High", "description": "Implement a mechanism to encrypt and decrypt ePHI.",
             "remediation": "Enable AES-256 encryption for ePHI at rest and TLS 1.2+ in transit. Document encryption decisions."},
            {"id": "TS-6", "ref": "§164.312(b)", "name": "Audit Controls", "required": "Required",
             "risk": "High", "description": "Implement hardware, software, and procedural mechanisms to record and examine activity.",
             "remediation": "Deploy comprehensive audit logging. Retain logs minimum 6 years. Implement log integrity monitoring."},
            {"id": "TS-7", "ref": "§164.312(c)(1)", "name": "Integrity Controls", "required": "Required",
             "risk": "High", "description": "Implement policies to protect ePHI from improper alteration or destruction.",
             "remediation": "Implement checksums, digital signatures, and file integrity monitoring for ePHI systems."},
            {"id": "TS-8", "ref": "§164.312(d)", "name": "Person or Entity Authentication", "required": "Required",
             "risk": "Critical", "description": "Implement procedures to verify that a person seeking access to ePHI is who they claim.",
             "remediation": "Deploy MFA for all systems accessing ePHI. Use strong password policies and privileged access management."},
            {"id": "TS-9", "ref": "§164.312(e)(1)", "name": "Transmission Security", "required": "Required",
             "risk": "Critical", "description": "Implement technical security measures to guard against unauthorized access to ePHI in transit.",
             "remediation": "Enforce TLS 1.2+ for all ePHI transmissions. Disable legacy protocols (SSL, TLS 1.0/1.1). Use VPN for remote access."},
        ]
    },
    "Organizational Requirements (§164.314)": {
        "weight": 10,
        "controls": [
            {"id": "OR-1", "ref": "§164.314(a)(1)", "name": "Business Associate Contracts", "required": "Required",
             "risk": "Critical", "description": "Business associate contracts must meet specific HIPAA requirements.",
             "remediation": "Review all BAAs for compliance with 2013 Omnibus Rule requirements. Update non-compliant agreements."},
            {"id": "OR-2", "ref": "§164.314(b)(1)", "name": "Group Health Plan Requirements", "required": "Required",
             "risk": "Medium", "description": "Plan documents must be amended to require plan sponsors to safeguard ePHI.",
             "remediation": "Amend plan documents to include required HIPAA provisions. Review with legal counsel."},
        ]
    }
}

DATA_FILE = 'hipaa_assessment.json'

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=2)

def calculate_stats(data):
    all_controls = []
    for section in HIPAA_CONTROLS.values():
        all_controls.extend(section['controls'])
    
    total = len(all_controls)
    compliant = sum(1 for c in all_controls if data.get(c['id'], {}).get('status') == 'compliant')
    partial = sum(1 for c in all_controls if data.get(c['id'], {}).get('status') == 'partial')
    non_compliant = sum(1 for c in all_controls if data.get(c['id'], {}).get('status') == 'non_compliant')
    not_assessed = total - compliant - partial - non_compliant

    # Risk-weighted score
    risk_scores = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}
    total_weight = sum(risk_scores.get(c['risk'], 1) for c in all_controls)
    achieved = sum(
        risk_scores.get(c['risk'], 1) * (1.0 if data.get(c['id'], {}).get('status') == 'compliant'
                                          else 0.5 if data.get(c['id'], {}).get('status') == 'partial' else 0)
        for c in all_controls
    )
    risk_score = round(achieved / total_weight * 100, 1) if total_weight > 0 else 0

    # Critical gaps
    critical_gaps = [c for c in all_controls
                     if c['risk'] == 'Critical' and data.get(c['id'], {}).get('status') in ('non_compliant', '')]

    return {
        'total': total,
        'compliant': compliant,
        'partial': partial,
        'non_compliant': non_compliant,
        'not_assessed': not_assessed,
        'risk_score': risk_score,
        'critical_gaps': len(critical_gaps),
        'risk_level': 'Low' if risk_score >= 80 else 'Medium' if risk_score >= 60 else 'High' if risk_score >= 40 else 'Critical'
    }

@app.route('/')
def index():
    data = load_data()
    stats = calculate_stats(data)
    return render_template('index.html', controls=HIPAA_CONTROLS, data=data, stats=stats)

@app.route('/update', methods=['POST'])
def update():
    payload = request.get_json()
    data = load_data()
    data[payload['control_id']] = {
        'status': payload['status'],
        'notes': payload.get('notes', ''),
        'updated': datetime.now().isoformat()
    }
    save_data(data)
    return jsonify({'success': True, 'stats': calculate_stats(data)})

@app.route('/report')
def report():
    data = load_data()
    stats = calculate_stats(data)
    all_controls = []
    for section_name, section in HIPAA_CONTROLS.items():
        for c in section['controls']:
            c_data = data.get(c['id'], {})
            all_controls.append({**c, 'section': section_name,
                                  'status': c_data.get('status', 'not_assessed'),
                                  'notes': c_data.get('notes', ''),
                                  'updated': c_data.get('updated', '')})
    
    gaps = [c for c in all_controls if c['status'] in ('non_compliant', 'not_assessed')]
    gaps.sort(key=lambda x: {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}.get(x['risk'], 4))
    
    return render_template('report.html', controls=HIPAA_CONTROLS, data=data, stats=stats,
                           all_controls=all_controls, gaps=gaps,
                           export_date=datetime.now().strftime('%B %d, %Y'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)
