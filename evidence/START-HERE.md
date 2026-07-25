# EH-A1 Local Lab

This assessment target runs entirely on your own machine. It uses only Python
3.11 or newer from the standard library. It does not use Docker, a VPN, a cloud
account, package installation, or any programme-operated target.

1. Download your private assignment overlay from the Stage 5 room.
2. Start the lab with your exact evidence marker:

   `python3 local_lab.py --marker UBI-A5-REPLACE-ME --output lab-runtime`

3. Read `lab-runtime/assignment.json` and `lab-runtime/scope.csv` before sending
   any traffic. Only the two `IN` loopback endpoints are authorized.
4. Run your recon engine against the entry target. Stop after retrieving the
   runtime-generated `user.txt` value.
5. Stop the target with Ctrl-C and preserve
   `lab-runtime/target-request-ledger.jsonl` with your evidence.

Reading or modifying `local_lab.py` does not earn discovery credit. Grading uses
the engine's raw observations, deterministic normalized output, scope tests,
request accounting, interrupted-run behavior, fallback behavior, an unseen
fixture, and the artifact defense. Do not submit a modified lab runtime.
