# HydraDX-security
A collection of security resources relating to the HydraDX blockchain:

* [Audit Reports](/audit-reports)
* [Critical Vulnerability reports](/criticals.md)
* [Invariants Specification](/invariants)
* [Mitigation Mechanisms](/mitigation_mechanisms.md) - a set of mechanisms designed to safeguard against economic exploits
* [Threat Modelling](/threat_modelling.md) - a collection of known attack vectors

## Audit Reports
### July 2023 - Stableswap Security Audit by Runtime Verification
Conducted by [Runtime Verification](https://runtimeverification.com/), published in June 2022.  
Read the full report [here](/audit-reports/230724-Runtime-Verification-Stableswap-Security-Audit.pdf).

### June 2023 - EMA Oracle Security Audit by Runtime Verification
Conducted by [Runtime Verification](https://runtimeverification.com/), published in June 2022.  
Read the full report [here](/audit-reports/230619-Runtime-Verification-EMA-Oracle-Security-Audit.pdf).

### September 2022 - Omnipool Security Audit by Runtime Verification
Conducted by [Runtime Verification](https://runtimeverification.com/), published in September 2022.  
Read the full report [here](/audit-reports/220907-Runtime-Verification-Omnipool-Security-Audit.pdf).

### March 2022 - Omnipool Economic and Mathematical Audit by Blockscience
Conducted by [BlockScience](https://block.science/), published in March 2022.  
Addendum by the HydraDX team elaborating on some changes which were made after the audit was finished (pp 41 et seq), published in November 2022.  
Read the full report [here](/audit-reports/220322-BlockScience-Omnipool-Report+addendum-by-HydraDX.pdf).

## Invariants Specification
You can find the specification of the following groups of invariants:
* [System-level invariants](/invariants/system-level) - these relate to the global state of the system and must always hold
* [Function-level invariants](/invariants/function-level) - these must hold in relation to the execution of specific state-transition functions (extrinsics)
