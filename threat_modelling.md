# Threat modelling

## General

- Circumvent any of the mitigation mechanisms (eg through a price manipulation)

## Omnipool

- Sandwich attack on add/remove liquidity, since we do not have slippage limits on these transactions
- Attack exploiting assets with different decimal counts
- Price manipulation attacks
    - Price manipulation sandwiching add or remove liquidity
- Find the edges / limitations of our current attack prevention mechanisms (caps, withdrawal fees, trading fees)
- Large Omnipool LPs - extract value from other LPs by manipulating prices and withdrawing liquidity
- Attacks via XCM (cross-chain messaging) - eg fake minting on another parachain
- DDOS via fees

## Stableswap

- Attack on stableswap as A (amplification) changes
- Implications of having stablepool shares in the Omnipool - rounding, conversions, add/withdraw liquidity, IL from fees?
- Stableswap - manipulation via `withdraw_asset_amount` (buy / add liquidity), missing in Curve implementation
- Stableswap - manipulation via `add_liquidity_shares` (buy / add liquidity), missing in Curve implementation

## Oracles
- Correct oracle price and liquidity update via Omnipool and Stableswap hooks.
- Oracle price manipulation
    - What damage can be done? (withdrawal limits, DCA)

## Circuit breaker
- manipulating blocking add/remove liquidity
- manipulate trade volume limits

## LBP
- Attack on LBP taking advantage of exponent implementation
