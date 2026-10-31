# Security policy

BountyProof deliberately contains vulnerable educational implementations. Use only the included fictional fixtures on an isolated owned workstation. Never expose the lab through a public interface, reverse proxy, tunnel or cloud deployment. Never remove the immutable input cages. Source publication is permitted; public vulnerable service deployment is not.

Expected weaknesses are the ten catalog scenarios in vulnerable mode. Unintended issues include cage bypasses, external network access, management authorization bypass, arbitrary file/command access or vulnerabilities in corrected implementations. Please use GitHub private vulnerability reporting if available, or contact the owner privately through their GitHub profile. Do not post secrets in a public issue. This project offers no bounty program.

No personal credentials or real data belong in fixtures, reports or screenshots. Fixture bearer strings, passwords and JWT keys are public, fictional constants. Management tokens are generated at startup, printed only locally, never committed and never stored in browser storage. Revoke them by restarting management. The app has no account integration.

See docs/THREAT_MODEL.md for trust assumptions and residual risks. SAST allowlisting applies only to exact reviewed vulnerable sinks. Fixed code and management surfaces are never blanket-excluded. CI runs regression, browser, dependency and container gates; passing gates are evidence of the tested cases, not a comprehensive security guarantee.
