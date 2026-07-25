# Ethical Hacking Advanced 1: Recon Engine and Foothold

## Authorization

Only the loopback endpoints marked `IN` by the supplied local lab are
authorized. Every intern receives the same self-contained lab and parser
fixtures. The lab derives one of six behavior profiles from the private room
marker and creates fresh credentials, route proof, ports, and a foothold flag
on each start. The asset marked `OUT` in `scope.csv` is a scope-discipline test.
Do not probe it. No programme VPN, hosted target, cloud account, container
runtime, package install, or internet connection is required.

## Window and scoring

Monday 09:00 WAT to Friday 18:10 WAT. One revision. 100 points: scope and safety 20, engine design and
tests 25, discovery completeness 20, foothold proof 20, evidence/reporting 15.
A scope breach or activity against a third party is an automatic fail.

## Build contract

Your CLI must accept `--target`, `--scope`, `--output`, and `--rate`; parse XML,
JSON, and line-oriented tool output into one versioned schema without shell
string concatenation; preserve raw output; generate JSON and a readable report;
enforce a request budget; and never auto-exploit. Interrupted runs must resume
without repeating completed probes. If one external tool is missing, a
documented fallback must complete the supported discovery path.

Start the target with Python 3.11 or newer and the exact marker in your private
assignment overlay. It binds only to `127.0.0.1`, writes `assignment.json` and
`scope.csv`, and uses nonstandard port mapping, a line protocol, wildcard HTTP
responses, and virtual-host routing. A default scan will not reveal enough to
earn the foothold. Your tool must adapt based on observed responses. Obtain
`user.txt`, record the runtime value, and stop.

## Proof

- Repository history with small, meaningful commits and tests.
- Raw output mapped to normalized records.
- `scope.csv` showing the decoy was not touched.
- Foothold transcript and `user.txt` marker.
- `make test` passing public parser, scope, wildcard, resume, failure, and
  normalization fixtures.
- Staff run 20 unreleased parser/scope fixtures and restart the local target
  under a different profile. Service recall must be at least 90 percent, with
  zero out-of-scope requests and no more than the 240-request budget.
- Staff interrupt one run and remove one external tool. The resumed/fallback run
  must produce the same normalized result hash as an uninterrupted run.
- Artifact check: implement one adapter against the documented interface.

The evidence marker shown in the room is not the `user.txt` foothold flag and
is never accepted as proof of access. A copied flag is also insufficient: the
raw response chain, target request ledger, normalized record, and defense must
reconcile. Reading or changing `local_lab.py` earns no discovery credit.

Scanner output without validation is not a finding. A shell command pasted
into a monolithic script is not a tested module.

## Mission interface and handoff

- **You receive:** one shared self-contained target and fixture pack plus a private marker that selects your runtime profile.
- **You build:** resumable scope-safe discovery with typed observations, runtime identifiers, rate limits, evidence capture, and cleanup.
- **You prove:** the foothold comes through the observed protocol chain and every request remains inside the generated scope ledger.
- **You hand forward:** discovery adapters, the runtime identifier model, evidence ledger, and cleanup interface for Stage 6.
