
import json
from . import diagnosis

def make_report(results, json_out=False):
    if json_out:
        return json.dumps(results, indent=2)
    else:
        lines = ["# NetDoctor Report\n"]
        for site, res in results.items():
            lines.append(f"## {site}")
            for k,v in res.items():
                lines.append(f"- {k}: {v}")
            lines.append("\n### Diagnosis")
            for note in diagnosis.interpret(res):
                lines.append(f"- {note}")
            lines.append("")
        return "\n".join(lines)
