# Security Notes for inspire-pir

- **Supported variants**: InsPIRe^0 (NoPacking), InsPIRe^1 (OnePacking), InsPIRe^2 (Seeded+Packed). These are the only production-supported modes.
- **Removed variant**: The experimental modulus-switching path (often called InsPIRe^2+) has been **removed** because modulus-switch noise exceeded the decryption bound with default parameters. The code, APIs, benches, and docs no longer expose or endorse this variant.
- **Do not re-enable**: Reintroducing modulus switching without a fresh, audited noise analysis will lead to correctness failures and potential privacy leaks. If you need to explore it for research, work off a historical commit in a separate branch and gate it behind an explicit, non-default feature flag.
- **Reporting issues**: Please open a GitHub issue in this repository with a minimal reproduction or description. Avoid including sensitive data in issue text.
