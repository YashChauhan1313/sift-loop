# Dataset & Test Environment Documentation

### Environment Specifications
- **Operating System:** Protocol SIFT Workstation (Ubuntu-based Forensic Environment)
- **Runtime:** Python 3.10+
- **AI Model:** Llama-3.3-70b-versatile (via Groq Cloud API)

### Test Data
For the hackathon submission, the agent was tested against the following:
1. **Local Filesystem Metadata:** Execution of `exiftool` against `triage_agent.py` to verify non-destructive data extraction.
2. **Synthetic Failure Data:** Execution of `ls -z` (invalid flag) to trigger the Persistent Learning Loop.
3. **Directory Listings:** Standard `ls -la` triage on the project root to verify basic command parsing.

### Verification Steps
To reproduce the agent's behavior:
1. Ensure `GROQ_API_KEY` is set.
2. Run `python3 triage_agent.py "ls -z"`.
3. Observe the agent identifying the `invalid option -- 'z'` error and self-correcting to a valid `ls` command.
