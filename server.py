from datetime import datetime
import os
import re
import ipaddress
from io import BytesIO
from urllib.parse import urlparse
from xml.sax.saxutils import escape

from flask import Flask, request, jsonify, send_file

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)


# --------------------------------------------------
# APPLICATION SETUP
# --------------------------------------------------

app = Flask(__name__, static_folder=".", static_url_path="")

app.config["MAX_CONTENT_LENGTH"] = 16 * 1024


# --------------------------------------------------
# HOME PAGE
# --------------------------------------------------

@app.route("/")
def home():
    return send_file(
        os.path.join(app.root_path, "index.html")
    )


# --------------------------------------------------
# WEBSITE SECURITY ANALYSIS
# --------------------------------------------------

def analyze_website(website):

    if not isinstance(website, str):
        raise ValueError("Website address must be text.")

    website = website.strip()

    if not website:
        raise ValueError("Website address is required.")

    if len(website) > 2048:
        raise ValueError("Website address is too long.")

    if not re.match(r"^https?://", website, re.IGNORECASE):
        raise ValueError(
            "Enter a complete HTTP or HTTPS address."
        )

    try:
        parsed = urlparse(website)
        hostname = parsed.hostname

    except ValueError:
        raise ValueError("Invalid website address.")

    if not hostname:
        raise ValueError("Invalid website address.")

    hostname = hostname.lower()

    warnings = []
    risk_score = 0

    # Check for direct IP addresses.

    try:
        ipaddress.ip_address(hostname)

        warnings.append(
            "Website uses a direct IP address instead of a domain name."
        )

        risk_score += 25

    except ValueError:
        pass

    # Check for suspicious keywords.

    suspicious_patterns = [
        "login",
        "verify",
        "secure",
        "account",
        "update",
        "password",
        "banking",
        "free",
        "gift",
        "prize"
    ]

    for pattern in suspicious_patterns:

        if pattern in hostname:

            warnings.append(
                f"Domain contains a potentially suspicious keyword: {pattern}."
            )

            risk_score += 20

    # Check unusual hyphen usage.

    if hostname.count("-") >= 3:

        warnings.append(
            "Domain contains an unusually high number of hyphens."
        )

        risk_score += 10

    # Check long number sequences.

    if re.search(r"\d{5,}", hostname):

        warnings.append(
            "Domain contains a long sequence of numbers."
        )

        risk_score += 10

    # Check HTTPS.

    if parsed.scheme.lower() != "https":

        warnings.append(
            "Website does not use HTTPS."
        )

        risk_score += 15

    # Check embedded credentials.

    if parsed.username or parsed.password:

        warnings.append(
            "Address contains embedded login information."
        )

        risk_score += 30

    # Check internationalized domain encoding.

    if "xn--" in hostname:

        warnings.append(
            "Domain uses internationalized encoding."
        )

        risk_score += 15

    # Keep score within the permitted range.

    risk_score = min(risk_score, 100)

    # Determine risk level.

    if risk_score >= 40:
        risk_level = "High"

    elif risk_score >= 20:
        risk_level = "Moderate"

    else:
        risk_level = "Low"

    status = (
        "Warning"
        if warnings
        else "No basic URL warnings detected"
    )

    return {
        "website": website,
        "warnings": warnings,
        "status": status,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "disclaimer": (
            "This basic analysis does not establish "
            "whether a website is safe."
        )
    }


# --------------------------------------------------
# WEBSITE SCANNER ROUTE
# --------------------------------------------------

@app.route("/scan-website", methods=["POST"])
def scan_website():

    data = request.get_json(silent=True) or {}

    website = data.get("website", "")

    try:

        results = analyze_website(website)

        return jsonify(results)

    except ValueError as error:

        return jsonify({
            "error": str(error)
        }), 400

    except Exception:

        app.logger.exception("Website scanning error")

        return jsonify({
            "error": "An unexpected scanning error occurred."
        }), 500


# --------------------------------------------------
# SECURITY RECOMMENDATIONS
# --------------------------------------------------

def generate_recommendations(warnings):

    recommendations = []

    warning_text = " ".join(warnings).lower()

    if "https" in warning_text:

        recommendations.append(
            "Avoid entering sensitive information on websites "
            "that do not use HTTPS."
        )

    if "suspicious keyword" in warning_text:

        recommendations.append(
            "Verify the website's identity and domain name "
            "before entering personal information."
        )

    if "ip address" in warning_text:

        recommendations.append(
            "Verify that the IP address belongs to the "
            "organization claiming to operate the website."
        )

    if "embedded login" in warning_text:

        recommendations.append(
            "Avoid URLs containing embedded usernames "
            "or passwords."
        )

    if "internationalized encoding" in warning_text:

        recommendations.append(
            "Check carefully for look-alike characters "
            "in the domain name."
        )

    if "hyphens" in warning_text:

        recommendations.append(
            "Double-check unusually formatted domain names."
        )

    if not recommendations:

        recommendations.append(
            "Continue practicing safe browsing and avoid "
            "sharing sensitive information with unverified websites."
        )

    return recommendations


# --------------------------------------------------
# PDF REPORT GENERATION
# --------------------------------------------------

@app.route("/download-report", methods=["POST"])
def download_report():

    data = request.get_json(silent=True)

    if not isinstance(data, dict):

        return jsonify({
            "error": "No report data provided."
        }), 400

    website = data.get("website", "")

    try:

        # Reanalyze the website instead of trusting
        # scores supplied by the browser.

        results = analyze_website(website)

    except ValueError as error:

        return jsonify({
            "error": str(error)
        }), 400

    try:

        pdf_buffer = BytesIO()

        document = SimpleDocTemplate(
            pdf_buffer,
            pagesize=letter,
            rightMargin=50,
            leftMargin=50,
            topMargin=50,
            bottomMargin=50
        )

        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            "CyberShieldTitle",
            parent=styles["Title"],
            textColor=colors.HexColor("#f5c16c"),
            alignment=TA_CENTER,
            fontSize=22
        )

        story = []

        # Report title.

        story.append(
            Paragraph("CYBERSHIELD", title_style)
        )

        story.append(
            Paragraph(
                "Website Security Assessment Report",
                styles["Heading2"]
            )
        )

        story.append(Spacer(1, 20))

        # Report information.

        report_details = [
            ["Website", results["website"]],
            [
                "Date",
                datetime.now().strftime(
                    "%B %d, %Y %I:%M %p"
                )
            ],
            ["Status", results["status"]],
            [
                "Risk Score",
                f'{results["risk_score"]}/100'
            ],
            ["Risk Level", results["risk_level"]]
        ]

        details_table = Table(
            report_details,
            colWidths=[110, 350]
        )

        details_table.setStyle(
            TableStyle([
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.HexColor("#2c3e50")
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (0, -1),
                    colors.white
                ),
                (
                    "BACKGROUND",
                    (1, 0),
                    (1, -1),
                    colors.HexColor("#eeeeee")
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey
                ),
                (
                    "PADDING",
                    (0, 0),
                    (-1, -1),
                    9
                )
            ])
        )

        story.append(details_table)
        story.append(Spacer(1, 20))

        # Risk classification.

        risk_color = {
            "Low": "#198754",
            "Moderate": "#f39c12",
            "High": "#dc3545"
        }.get(results["risk_level"], "#34495e")

        story.append(
            Paragraph(
                (
                    f'<font color="{risk_color}">'
                    f'<b>Risk Level: '
                    f'{escape(results["risk_level"])}</b>'
                    f'</font>'
                ),
                styles["Heading2"]
            )
        )

        story.append(
            Paragraph(
                f'Risk Score: {results["risk_score"]}/100',
                styles["Normal"]
            )
        )

        story.append(Spacer(1, 15))

        # Security warnings.

        story.append(
            Paragraph(
                "Security Warnings",
                styles["Heading2"]
            )
        )

        if results["warnings"]:

            for warning in results["warnings"]:

                story.append(
                    Paragraph(
                        "- " + escape(warning),
                        styles["Normal"]
                    )
                )

                story.append(Spacer(1, 5))

        else:

            story.append(
                Paragraph(
                    "No basic URL warnings detected.",
                    styles["Normal"]
                )
            )

        story.append(Spacer(1, 15))

        # Recommendations.

        story.append(
            Paragraph(
                "Security Recommendations",
                styles["Heading2"]
            )
        )

        recommendations = generate_recommendations(
            results["warnings"]
        )

        for recommendation in recommendations:

            story.append(
                Paragraph(
                    "- " + escape(recommendation),
                    styles["Normal"]
                )
            )

            story.append(Spacer(1, 5))

        story.append(Spacer(1, 25))

        # Disclaimer.

        story.append(
            Paragraph(
                "Disclaimer: This basic assessment does not "
                "guarantee website safety and is not a "
                "substitute for a professional security audit.",
                styles["Italic"]
            )
        )

        document.build(story)

        pdf_buffer.seek(0)

        return send_file(
            pdf_buffer,
            mimetype="application/pdf",
            as_attachment=True,
            download_name="CyberShield-Security-Report.pdf"
        )

    except Exception:

        app.logger.exception("PDF report generation error")

        return jsonify({
            "error": "Unable to generate the PDF report."
        }), 500


# --------------------------------------------------
# APPLICATION STARTUP
# --------------------------------------------------

print("CYBERSHIELD FILE:", app.root_path)

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        use_reloader=False
    )