"""
recon_engine.parsers.errors
============================
Parser error taxonomy. Every parser raises one of these instead of letting
a raw exception (KeyError, JSONDecodeError, etc.) leak out, so the
orchestrator can log a stable error code to errors.jsonl.

Matches PARSE-05 (MALFORMED_TOOL_OUTPUT) and PARSE-06 (REQUIRED_FIELD_MISSING).
"""


class ParserError(Exception):
    code: str = "PARSER_ERROR"

    def __init__(self, message: str, *, source_file: str = ""):
        super().__init__(message)
        self.message = message
        self.source_file = source_file

    def to_dict(self) -> dict:
        return {
            "error": self.code,
            "message": self.message,
            "source_file": self.source_file,
        }


class MalformedToolOutput(ParserError):
    code = "MALFORMED_TOOL_OUTPUT"


class RequiredFieldMissing(ParserError):
    code = "REQUIRED_FIELD_MISSING"