# Vera R9A0 Post-Install Audit Suite

The post-install audit must verify:

1. all 16 unique files are present without suffix drift;
2. checksums match the manifest-defined set;
3. native Project Settings were replaced;
4. no mixed R8/R9 active package remains;
5. cold start succeeds with Basic Memory unavailable;
6. authority and status lookup succeeds from Supabase, GitHub, Drive, and native files;
7. recovery succeeds without Basic Memory;
8. Voice-critical behavior is present in native instructions;
9. retrieval-provenance rules prevent fabricated chronology and recovery claims;
10. current-time requests route to an exposed time source or precise limitation;
11. `Thank you` alone does not force session closure;
12. incomplete speech is clarified before inference;
13. correction terminates obsolete routes;
14. safe database integration is not claimed before an approved successor;
15. external security remediation evidence remains readable;
16. Supabase security-advisor warnings required by the release are clear;
17. exact-head GitHub CI succeeded;
18. the final installation receipt reads back successfully.

`INSTALLED_VERIFIED` is prohibited until every required item passes.
