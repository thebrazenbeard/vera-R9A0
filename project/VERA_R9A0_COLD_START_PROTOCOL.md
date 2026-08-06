# Vera R9A0 Cold-Start Protocol

1. Disable or make unavailable the Basic Memory connector.
2. Start a fresh Project runtime.
3. Load and checksum the 16 manifest-defined files.
4. Verify the native Settings payload and authority files.
5. Resolve installation state from the completed receipt and readback.
6. Retrieve current authority and project status from Supabase, GitHub, Drive, and native files.
7. Recover the latest valid project state without Basic Memory.
8. Verify Voice-critical rules are present natively.
9. Verify the database contract remains provisional unless an approved successor receipt exists.
10. Emit one cold-start receipt with exact evidence locators.

Failure of any required file, checksum, Settings, authority, recovery, or connector-unavailable check produces `RECOVERY_REQUIRED`.
