from time import sleep
from helpers.factory import get_integrations
from models.attachment_results import AttachmentResults
from config import config
from utils import get_logger
from db.session import SessionLocal
from models.attachments import Attachments
from sqlalchemy.orm import Session
import threading

logger = get_logger()


class AttachmentAnalyzer:
    def __init__(self, db: Session, integrations: dict):
        self.db = db
        self.integrations = integrations

    def start_analysis(self, attachment_obj: Attachments):
        sha256 = attachment_obj.file_sha256
        for integration in self.integrations:
            integration_obj = integration["class"]
            integration_name = integration["name"]
            result, is_malicious = integration_obj.get_file_analysis(sha256)
            if not result:
                continue

            data_to_push = {
                "attachment_id": attachment_obj.id,
                "integration_name": integration_name,
                "is_malicious": is_malicious,
                "result": result,
            }
            AttachmentResults.create(self.db, **data_to_push)

        Attachments.update(self.db, attachment_obj.id, is_analyzed=True)


def analyze_attachments():
    logger.info("Starting Attachment Analyzer now.")
    avaliable_integrations = get_integrations()
    if not avaliable_integrations:
        logger.info(f"No integrations found. Stopping Attachment Analyzer.")
        return
    while 1:
        db = SessionLocal()
        count = 0
        analyzer_obj = AttachmentAnalyzer(db, avaliable_integrations)
        query = {"is_analyzed": False}
        for attachment_obj in Attachments.get_all(db, query):
            logger.info(f"Analyzing Attachment: {attachment_obj.id}")
            count += 1
            analyzer_obj.start_analysis(attachment_obj)

        if not count:
            sleep(30)


# Start the attachment analysis
def start_attachment_analysis():
    analyzer_thread = threading.Thread(target=analyze_attachments)

    # Allow the thread to exit when the main program exits
    analyzer_thread.daemon = True
    analyzer_thread.start()
