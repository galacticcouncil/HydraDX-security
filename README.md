# HydraDX-security
This repository contains the following security resources relating to the HydraDX blockchain:

* [Audit Reports](https://github.com/galacticcouncil/HydraDX-security/audit-reports)
* [Invariants Specification](https://github.com/galacticcouncil/HydraDX-security/invariants)

## Audit Reports
### September 2022 - Omnipool Security Audit by Runtime Verification
Conducted by [Runtime Verification](https://runtimeverification.com/), published in September 2022.  
Read the full report [here](https://github.com/galacticcouncil/HydraDX-security/audit-reports/220907-Runtime-Verification-Security-Audit.pdf).

### March 2022 - Omnipool Economic and Mathematical Audit by Blockscience
Conducted by [BlockScience](https://block.science/), published in March 2022.  
Addendum by the HydraDX team elaborating on some changes which were made after the audit was finished (pp 41 et seq), published in November 2022.  
Read the full report [here](https://github.com/galacticcouncil/HydraDX-security/audit-reports/220322-BlockScience-Omnipool-Report+addendum-by-HydraDX.pdf).

## Invariants Specification
You can find the specification of the following groups of invariants:
* [System-level invariants](https://github.com/galacticcouncil/HydraDX-security/invariants/system-level) - these relate to the global state of the system and must always hold
* [Function-level invariants](https://github.com/galacticcouncil/HydraDX-security/invariants/function-level) - these must hold in relation to the execution of specific state-transition functions (extrinsics)
