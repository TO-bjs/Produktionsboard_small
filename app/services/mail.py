import smtplib
import traceback
from email.message import EmailMessage


def send_email(subject, body, to_email):
    try:
        msg = EmailMessage()
        msg['Subject'] = subject
        msg['From'] = 'it@to-labsystems.de'
        msg['To'] = to_email
        msg.set_content(body)

        with smtplib.SMTP_SSL('smtp.strato.de', 465, timeout=10) as smtp:
            smtp.login('it@to-labsystems.de', 'Labsys-InfoTech25/')
            smtp.send_message(msg)

        print('✅ E-Mail erfolgreich gesendet an', to_email)
    except Exception:
        print('❌ Fehler beim Senden der E-Mail:')
        traceback.print_exc()
