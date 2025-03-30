from sqlalchemy import (
    Column,
    BIGINT,
    ForeignKey,
    String,
    CHAR,
    Boolean,
    UniqueConstraint,
)
from sqlalchemy.dialects import postgresql
from models.base import Base, CRUDBase, TimeStampedMixin


class AttachmentResults(Base, CRUDBase, TimeStampedMixin):
    __tablename__ = "attachment_result"

    id = Column(BIGINT, primary_key=True, index=True)
    attachment_id = Column(BIGINT, ForeignKey("attachments.id"), nullable=False)
    integration_name = Column(String, nullable=False)
    is_malicious = Column(Boolean, default=False, server_default="false")
    result = Column(postgresql.JSON, default={}, server_default="{}")

    __table_args__ = (
        UniqueConstraint(
            "attachment_id", "integration_name", name="uix_attachment_integration"
        ),
    )
