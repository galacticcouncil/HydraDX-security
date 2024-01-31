# Critical Vulnerabilities (mitigated)

### critical-2304
Reported and mitigated critical vulnerability in the Omnipool, related to extracting value from other LPs by manipulating the price of the pool token LRNA.

- Example of attack before mitigation:
    - Attacker buys TKN (increasing value of TKN)
    - Attacker adds some amount of liquidity in TKN (causes LRNA to be minted at increased value of TKN)
    - Attacker arbitrages Omnipool back to initial prices (prices between different assets, *not* including LRNA)
    - Attacker removes their liquidity in TKN
- This attack could start with all assets at market prices (denominated in USD or something other than LRNA) and end with all assets back at initial prices, *except* for LRNA. The change in value in LRNA would correspond to profit picked up by the arbitrager, which could be extracted entirely in other assets (i.e. not LRNA).
- Note that other versions of this attack were also profitable. Versions where liquidity was added at initial prices and then withdrawn at manipulated prices, etc.
- Mitigations
    - Users cannot add or remove liquidity if LRNA/TKN EMA oracle price differs from LRNA/TKN spot price by more than 1%.
    - If oracle price and spot price differ but are within 1%, withdrawal is allowed but a fee is charged equal to the % difference between the spot and oracle prices.
    - The amount of liquidity that can be added to or withdrawn from Omnipool in a single block is capped at 5% of existing Omnipool liquidity of that asset.
- We believe these mitigations force the market manipulation to be sustained over multiple blocks, which should make the attack impossible to carry out profitably.
