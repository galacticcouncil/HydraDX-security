# Stableswap

### Notation

| Variable | Description |
| --- | --- |
| $R_i$ | Stableswap reserve of asset $i$ |
| $S$ | Shares in stableswap pool |
| $D$ | Stableswap invariant |

For a given state variable $X$, we will generally denote the value of $X$ *after* the operation by $X^+$.

## Operation-specific

### Swap

- After a swap, we should have

$$
D + 5000 \geq D^+ \geq D
$$

### Add Liquidity (arbitrary assets)

- After adding liquidity, we should have

$$
D^+ \geq D\\
D^+ S \geq D S^+ \geq (D^+ - 1)S
$$

### Withdraw Liquidity (one asset)

- After removing liquidity, we should have

$$
D^+\leq D\\
D(S^+ + 1) \geq D^+ S \geq D S^+
$$
