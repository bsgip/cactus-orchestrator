def assert_pdf_file(pdf_data: bytes | None) -> None:
    assert pdf_data is not None
    assert len(pdf_data) >= 4
    assert b"%PDF" == pdf_data[0:4]
