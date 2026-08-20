import io
import zipfile


def _as_zipfile(z: bytes | zipfile.ZipFile) -> zipfile.ZipFile:
    if isinstance(z, zipfile.ZipFile):
        return z
    return zipfile.ZipFile(io.BytesIO(z))


def get_zip_arcfile_contents(z: bytes | zipfile.ZipFile, arcname: str) -> bytes | None:
    """Gets the contents of a specific file (arcname) within a zip. Returns None if that file/arc DNE"""
    zf = _as_zipfile(z)

    if arcname not in zf.namelist():
        return None

    return zf.read(arcname)


def assert_zips_equal(
    zip1: bytes | zipfile.ZipFile,
    zip2: bytes | zipfile.ZipFile,
    ignore_arcnames: set[str] | None = None,
) -> None:
    """
    Assert that two zip files contain the same files with the same contents.

    Args:
        zip1: First zip file, as raw bytes or an open zipfile.ZipFile.
        zip2: Second zip file, as raw bytes or an open zipfile.ZipFile.
        ignore_arcnames: Optional set of arcnames (paths inside the zip) to
            skip entirely when comparing -- they won't be checked for
            presence, absence, or content equality.

    Raises:
        AssertionError: if the zips differ in membership (accounting for
            ignored names) or if any shared, non-ignored file's contents
            differ.
    """
    ignore_arcnames = ignore_arcnames or set()

    zf1 = _as_zipfile(zip1)
    zf2 = _as_zipfile(zip2)

    names1 = {n for n in zf1.namelist() if n not in ignore_arcnames}
    names2 = {n for n in zf2.namelist() if n not in ignore_arcnames}

    only_in_1 = names1 - names2
    only_in_2 = names2 - names1

    if only_in_1 or only_in_2:
        msg_parts = []
        if only_in_1:
            msg_parts.append(f"only in first zip: {sorted(only_in_1)}")
        if only_in_2:
            msg_parts.append(f"only in second zip: {sorted(only_in_2)}")
        raise AssertionError("Zip files have different contents (" + "; ".join(msg_parts) + ")")

    mismatched = []
    for name in sorted(names1):
        data1 = zf1.read(name)
        data2 = zf2.read(name)
        if data1 != data2:
            mismatched.append(name)

    if mismatched:
        raise AssertionError(f"Zip files have differing contents for files: {mismatched}")
