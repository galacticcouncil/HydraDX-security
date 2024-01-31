# Mitigation mechanisms

HydraDX has the following mitigation mechanisms in place which act as safeguards against economic exploits:

### Circuit Breaker
- tracks and limits the percentage of the liquidity (asset reserve) of a pool that can be traded (net volume), added and removed in a block
- Three different limits are tracked independently for all assets: trading limit, liquidity added, and liquidity removed
- All trading volumes and amounts of liquidity are reset to zero at the end of block execution
- The limits are tracked for the Omnipool
- TradeVolumeLimitPerBlock = 50%
- AddLiquidityLimitPerBlock = 5%
- RemoveLiquidityLimitPerBlock = 5%

### Add / Remove Liquidity Restrictions
* adding and removing liquidity from the Omnipool is temporarily blocked if the EMA Oracle price has changed > 1%
* if the price change is <1%, a dynamif fee applies to all withdrawals, ranging from 0.01% to 1.00%

### TVL Limits
All tokens in the Omnipool have a cap which prevents from LPing a higher amount than what is predefined (as % of the total Omnipool TVL). Usually, lower cap assets will not make up more than 5-15% of the Omnipool TVL.
