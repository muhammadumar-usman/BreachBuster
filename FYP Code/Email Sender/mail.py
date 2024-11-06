import yagmail

def send_email_with_attachment(recipient_email, pdf_filename):
    # Initialize yagmail with your email credentials
    yag = yagmail.SMTP('mybusinessaipentesting@gmail.com', 'Hamaragroup@1')

    # Send email with attachment
    yag.send(
        to=recipient_email,
        subject="PDF Document Attached",
        contents="Please find the attached PDF document.",
        attachments=pdf_filename
    )
    print("Email sent successfully!")


# Example usage:
if __name__ == "__main__":
    recipient_email = "umarusman24402@gmail.com"
    pdf_filename = "pentesting_report.pdf"
    send_email_with_attachment(recipient_email, pdf_filename)
