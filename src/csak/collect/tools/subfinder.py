"""Subfinder catalog module.

Tool flags and output format documented at
``cyber-wiki/wiki/research/slice-2-tool-output-reference.md``.

Subfinder enumerates passive subdomain sources and emits one JSON
object per discovered host. The slice 1 subfinder parser already
handles its JSONL output — slice 2 only needs invocation recipes,
target-type routing, and (trivially) progress + rate-limit handling
for the runner.

Subfinder doesn't expose a clean progress percent or a structured
rate-limit signal — both methods return the base-class default
(``None`` and ``False`` respectively). The runner falls back to
counting JSONL lines in the output file for live progress.
"""
from __future__ import annotations

from csak.collect.tool import Mode, RateLimitDefaults, TargetType, Tool


# Per-mode flag recipes. Source attributions follow each recipe.
INVOCATIONS: dict[Mode, list[str]] = {
    "quick": [
        # Passive sources only — subfinder's default behavior. No -all.
        # source: reconFTW v4.0 modules/subdomains.sh (passive recipe)
        "-silent", "-oJ", "-nW", "-duc",
    ],
    "standard": [
        # source: reconFTW v4.0 modules/subdomains.sh (full passive recipe)
        "-silent", "-oJ", "-nW", "-duc", "-all",
    ],
    "deep": [
        # -recursive enables sources that recurse on found subdomains.
        # source: reconFTW v4.0 modules/subdomains.sh (deep recipe)
        "-silent", "-oJ", "-nW", "-duc", "-all", "-recursive",
    ],
}


class SubfinderTool(Tool):
    name = "subfinder"
    binary = "subfinder"
    minimum_version = "2.6.0"
    install_command = (
        "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    )
    output_filename = "subdomains.jsonl"
    rate_limit = RateLimitDefaults(
        start_rps=0,    # subfinder doesn't enforce a global RPS by default
        floor_rps=1,
        ceiling_rps=100,
        flag_name="-rl",
    )
    override_flags = {
        "rate_limit": "-rl",
    }

    def applies_to(self, target_type: TargetType) -> bool:
        # Per spec routing matrix: subfinder only applies to apex
        # domains. Subdomains, IPs, CIDRs, and URLs all skip it.
        return target_type == "domain"

    def invocation(
        self,
        *,
        target: str,
        target_type: TargetType,
        mode: Mode,
        input_file: str | None,
        output_file: str,
        overrides: dict[str, str] | None = None,
    ) -> list[str]:
        argv = list(INVOCATIONS[mode])
        argv.extend(["-d", target, "-o", output_file])
        for key, value in (overrides or {}).items():
            flag = self.override_flags.get(key)
            if flag is None:
                continue
            argv.extend([flag, value])
        return argv


SUBFINDER = SubfinderTool()
