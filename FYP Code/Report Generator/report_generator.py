from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image as RLImage, Frame
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
import matplotlib.pyplot as plt
from io import BytesIO
from datetime import datetime
import numpy as np
from reportlab.lib.units import inch
from datetime import datetime

def generate_pdf(file_name, vulnerability_data):
    # Get the current date and time
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Create a PDF document
    doc = SimpleDocTemplate(file_name, pagesize=letter,
                            leftMargin=0.5*inch, rightMargin=0.5*inch,
                            topMargin=0.5*inch, bottomMargin=0.5*inch)

    # Create a frame for the content with a solid line border
    content_frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, 
                          id='normal', showBoundary=1, topPadding=0.5*inch)
    styles = getSampleStyleSheet()

    # Add the logo
    logo_path = "logo.png"
    logo = RLImage(logo_path)
    logo.drawHeight = 1.2 * inch  
    logo.drawWidth = 1.5 * inch     
    content_elements = [logo]



    # Add title
    title = Paragraph("PENETRATION TEST REPORT", styles["Title"])
    content_elements.append(title)

    # Add two lines space after title
    content_elements.append(Spacer(1, 24))

    # Add time of report generation
    generation_time = Paragraph(f"Report generated on: {current_time}", styles["Normal"])
    content_elements.append(generation_time)
    # Add two lines space after title
    content_elements.append(Spacer(1, 24))
    
    # Iterate through vulnerability data
    for vulnerability_list in vulnerability_data:
        for vulnerability in vulnerability_list:
            # Generate table for vulnerability data
            title = vuln_title(vulnerability)
            content_elements.append(title)
            content_elements.append(Spacer(1, 24))
            table = generate_table(vulnerability)
            content_elements.append(table)

            # Add short description outside the table
            content_elements.append(Spacer(1, 24))
            short_description = generate_short_description(vulnerability)
            content_elements.append(short_description)
            content_elements.append(Spacer(1, 24))
            content_elements.append(Spacer(1, 24))

            # Generate and add bar chart
            graph_data = generate_all_bar_charts(vulnerability[1].get("cve_id", ""), 
                                                  vulnerability[1].get("cvss", ""),
                                                  vulnerability[1].get("complexity", ""),
                                                  vulnerability[1].get("severity", ""))
            content_elements.append(graph_data)

            # Add exploit description
            content_elements.append(Spacer(1, 24))
            short_description = generate_exploit_description(vulnerability)
            content_elements.append(short_description)
            content_elements.append(Spacer(1, 24))
            content_elements.append(Spacer(1, 24))

            # Add exploit code
            content_elements.append(Spacer(1, 24))
            short_description = generate_exploit_code(vulnerability)
            content_elements.append(short_description)
            content_elements.append(Spacer(1, 24))
            content_elements.append(Spacer(1, 24))

            # Add space between vulnerabilities
            content_elements.append(Spacer(1, 24))
            content_elements.append(Spacer(1, 24))

    # Build the document
    doc.build(content_elements)


def generate_table(vulnerability):
    # Transpose table data
    table_data = [
        ["Field", "Value"],
        ["Target", vulnerability[1].get("target", "")],
        ["Identified Technology", vulnerability[1].get("selected_techn", "")],
        ["CVE ID", vulnerability[1].get("cve_id", "")],
        ["Vulnerability Type", vulnerability[1].get("vuln_type", "")],
        ["Required Action", vulnerability[1].get("required_action", "")],
        ["Publish Date", vulnerability[1].get("pub_date", "")],
        ["CVSS", vulnerability[1].get("cvss", "")],
        ["CWE", vulnerability[1].get("cwe", "")],
        ["Vector", vulnerability[1].get("vector", "")],
        ["Complexity", vulnerability[1].get("complexity", "")],
        ["Severity", vulnerability[1].get("severity", "")]
    ]

    # Create table
    table = Table(table_data, colWidths=[150, 350])
    table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                               ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                               ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                               ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                               ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                               ('GRID', (0, 0), (-1, -1), 1, colors.black)]))

    return table



def generate_short_description(vulnerability):
    description_heading = "DESCRIPTION: "
    description_text = vulnerability[1].get("description", "")
    description_paragraph = f"<b>{description_heading}</b>{description_text}"
    return Paragraph(description_paragraph, getSampleStyleSheet()["Normal"])


def generate_exploit_description(vulnerability):
    description_heading = "EXPLOIT DESCRIPTION: "
    description_text = vulnerability[1].get("exploit_details", "")
    description_paragraph = f"<b>{description_heading}</b>{description_text}"
    return Paragraph(description_paragraph, getSampleStyleSheet()["Normal"])

def generate_exploit_code(vulnerability):
    description_heading = "EXPLOIT CODE: "
    description_text = vulnerability[1].get("exploit_code", "")
    # Replace '\n' with '<br/>' for HTML interpretation in the Paragraph
    description_text = description_text.replace("\n", "<br/>")
    description_paragraph = f"<b>{description_heading}</b>{description_text}"
    return Paragraph(description_paragraph, getSampleStyleSheet()["Normal"])


def vuln_title(vulnerability):
    description_heading = "TESTED VULNERABILITY : "
    description_paragraph = f"<b>{description_heading}</b>"
    return Paragraph(description_paragraph, getSampleStyleSheet()["Normal"])


def generate_all_bar_charts(vulnerability_name, cvss_score, complexity, severity):
    # Create a figure with three subplots
    fig, axs = plt.subplots(1, 3, figsize=(3.5, 1.8))

    # Determine color for CVSS score
    cvss_color = 'blue'


    # Determine color for complexity
    if complexity == 'LOW':
        complexity_color = 'green'
    elif complexity == 'MED':
        complexity_color = 'blue'
    else:
        complexity_color = 'red'

    # Determine color for severity
    if severity == 'HIGH':
        severity_color = 'red'
    elif severity == 'MEDIUM':
        severity_color = 'orange'
    else:
        severity_color = 'green'

    # Plot bar chart for CVSS score
    axs[0].bar(vulnerability_name, cvss_score, color=cvss_color)
    axs[0].set_ylabel('CVSS Score', fontsize=8)
    axs[0].set_ylim(0, 10)
    axs[0].tick_params(axis='both', which='both', labelsize=7)
    axs[0].text(vulnerability_name, cvss_score + 0.5, f"{cvss_score}", ha='center', va='bottom')

    # Plot bar chart for complexity
    axs[1].bar(vulnerability_name, 1, color=complexity_color)
    axs[1].set_ylabel('Complexity', fontsize=8)
    axs[1].set_ylim(0, 1)
    axs[1].tick_params(axis='both', which='both', labelsize=7)
    axs[1].text(vulnerability_name, 1.05, f"{complexity}", ha='center', va='bottom')

    # Plot bar chart for severity
    axs[2].bar(vulnerability_name, 1, color=severity_color)
    axs[2].set_ylabel('Severity', fontsize=8)
    axs[2].set_ylim(0, 1)
    axs[2].tick_params(axis='both', which='both', labelsize=7)
    axs[2].text(vulnerability_name, 1.05, f"{severity}", ha='center', va='bottom')

    # Remove x and y ticks for the second and third subplots
    for ax in axs[1:]:
        ax.set_yticks([])


    # Adjust layout to prevent overlap
    plt.tight_layout(pad=1)

    # Save the plot to a BytesIO object
    img_io = BytesIO()
    plt.savefig(img_io, format='png', bbox_inches='tight')
    img_io.seek(0)

    return RLImage(img_io)









def prepare_vulnerability_data(data):
    # Extract relevant information from the input data dictionary
    cve_id = data.get('CVE ID', 'N/A')
    description = data.get('Description', 'No description provided')
    publish_date = data.get('Publish Date', 'N/A')
    cvss_score = data.get('Score', [0, 'N/A'])[1]  # Extract the CVSS score
    short_description = description.split('.')[0] if '.' in description else description  # Extract the first sentence for short description
    severity = data.get('Score', [0, 0, '8.3'])[2]
    cwe = data.get('CWE', ['N/A'])[0]
    Refrence = data.get('Refrences', ['N/A'])[0]
    CPE = data.get('CPE', ['N/A'])[0]
    target = data.get('Target', 'N/A')
    tech = data.get('Selected Technology', 'N/A')
    exploit_details = data.get('Exploit_Details', 'N/A')
    exploit_code = data.get('Exploit_Code', 'N/A')

    # Prepare the vulnerability data in the expected format
    vulnerability_data = [
        [
            ('Vulnerability', {
                'target': target,
                'selected_techn': tech,
                'cve_id': cve_id,
                'vuln_type': 'Web',
                'Refrence': Refrence,
                'CPE': CPE,
                'pub_date': publish_date,
                'short_description': short_description,
                'required_action': 'Apply security updates as recommended by Vendor.',
                'cvss': cvss_score,
                'cwe': cwe,
                'vector': 'WEB',
                'complexity': 'MED',
                'severity': severity,
                'description': description,
                'exploit_details': exploit_details,
                'exploit_code': exploit_code,
            })
        ]
    ]

    return vulnerability_data



if __name__ == "__main__":

        # Sample vulnerability data dictionary
    vulnerability_data_dict = {
        'CVE ID': 'CVE-2021-41773',
        'Description': 'A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased paths, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.',
        'Publish Date': '2021-10-05T09:15:07.593',
        'Score': ['V31', 9.5, 'HIGH']
        # Other fields like NVD Link, CWE, References, CPE can also be included
    }


    prepare_vulnerability_data(vulnerability_data_dict)

    # Generate PDF report using the prepared vulnerability data
    generate_pdf("pentesting_report.pdf", prepare_vulnerability_data(vulnerability_data_dict))
