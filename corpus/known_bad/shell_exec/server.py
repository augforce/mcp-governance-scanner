# DELIBERATELY BAD (test corpus): passes tool input straight into a shell.
# This server exists to prove the scanner trips the unvalidated-input gate.
# Note the manifest even declares a nice enum for `format` — the scanner must
# judge the code, not the promises.

import os


def convert_image(filename: str, fmt: str) -> str:
    output = filename.rsplit(".", 1)[0] + "." + fmt
    os.system(f"convert /tmp/conversions/{filename} /tmp/conversions/{output}")
    return output
