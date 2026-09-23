import json
import tempfile
import unittest
from pathlib import Path

from checks.integrations import _read_json_or_jsonl


class IntegrationParsingTests(unittest.TestCase):
    def test_reads_json_array(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rows.json"
            path.write_text(json.dumps([{"name": "a.example"}, {"name": "b.example"}]), encoding="utf-8")
            self.assertEqual(len(_read_json_or_jsonl(path)), 2)

    def test_reads_json_lines_and_ignores_invalid_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rows.jsonl"
            path.write_text('{"name":"a.example"}\nnot-json\n{"name":"b.example"}\n', encoding="utf-8")
            self.assertEqual([row["name"] for row in _read_json_or_jsonl(path)], ["a.example", "b.example"])


if __name__ == "__main__":
    unittest.main()
