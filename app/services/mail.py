import logging
import smtplib
from email.message import EmailMessage

logger = logging.getLogger(__name__)


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

        logger.info('E-Mail erfolgreich gesendet an %s', to_email)
    except Exception:
        logger.exception('Fehler beim Senden der E-Mail an %s', to_email)
