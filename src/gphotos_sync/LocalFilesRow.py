import logging
from datetime import datetime
from pathlib import Path

from gphotos_sync.BaseMedia import BaseMedia
from gphotos_sync.DatabaseMedia import DatabaseMedia
from gphotos_sync.DbRow import DbRow
from gphotos_sync.LocalFilesMedia import LocalFilesMedia

log = logging.getLogger(__name__)


@DbRow.db_row
class LocalFilesRow(DbRow):
    """
    generates a class with attributes for each of the columns in the
    LocalFiles table
    """

    table = "LocalFiles"
    cols_def = {
        "Id": int,
        "RemoteId": str,
        "Uid": str,
        "Path": str,
        "FileName": str,
        "OriginalFileName": str,
        "DuplicateNo": int,
        "MimeType": str,
        "Description": str,
        "FileSize": int,
        "ModifyDate": datetime,
        "CreateDate": datetime,
        "SyncDate": datetime,
    }
    no_update = ["Id"]

    def to_media(self) -> DatabaseMedia:
        pth = Path(self.Path) if self.Path else None
        db_media = DatabaseMedia(
            _id=self.RemoteId,
            _relative_folder=pth,
            _filename=self.FileName,
            _orig_name=self.OriginalFileName,
            _duplicate_number=self.DuplicateNo,
            _size=self.FileSize,
            _mime_type=self.MimeType,
            _description=self.Description,
            _date=self.ModifyDate,
            _create_date=self.CreateDate,
        )
        return db_media

    @classmethod
    def from_media(cls, media: LocalFilesMedia) -> "LocalFilesRow":
        now_time = datetime.now().strftime(BaseMedia.TIME_FORMAT)
        new_row = cls.make(
            Path=str(media.relative_folder),
            Uid=media.uid,
            FileName=media.filename,
            OriginalFileName=media.orig_name,
            DuplicateNo=media.duplicate_number,
            FileSize=media.size,
            MimeType=media.mime_type,
            Description=media.description,
            ModifyDate=media.modify_date,
            CreateDate=media.create_date,
            SyncDate=now_time,
        )
        return new_row
