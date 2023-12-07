# Function Level

### Notation

| Variable | Description |
| --- | --- |
| $R_i$ | Omnipool reserves of asset $i$ |
| $Q_i$ | LRNA in subpool for asset $i$ |
| $S_i$ | Shares in asset $i$ subpool |
| $\omega_i$ | Weight cap for asset $i$ in Omnipool |

For a given state variable $X$, we will generally denote the value of $X$ *after* the operation by $X^+$.

[Omnipool Specification](https://github.com/galacticcouncil/HydraDX-simulations/blob/main/hydradx/spec/OmnipoolSpec.ipynb)

## Function-level Invariants

### Swap

- For all assets $i$ in Omnipool, the invariant $R_i Q_i$ should not decrease due to a swap. This means that after a swap for all assets $i$ in Omnipool:

$$
R_i^+ Q_i^+ \geq R_i Q_i
$$

- $R_iQ_i$ should be invariant, but one is calculated from the other. If e.g. $R_i^+$ is calculated it may have error up to $1$, in which case the product $R_i^+Q_i^+$ may have error up to $Q_i^+$. If $Q_i^+$ is calculated, then the product has error up to $R_i^+$. Thus we should always be able to bound the error by $max(R_i^+,Q_i^+)$, giving us

$$
R_i Q_i + max(R_i^+, Q_i^+) \geq R_i^+ Q_i^+
$$

### Add liquidity

- Add liquidity should respect price $\frac{Q_i}{R_i}$. This means $\frac{Q_i}{R_i} = \frac{Q_i^+}{R_i^+}$, or $Q_i R_i^+ = Q_i^+ R_i$. What is most important here is not which direction we round but the accuracy. So we must test that

$$
(Q_i^+ - 1)R_i \leq Q_i R_i^+ \leq (Q_i^+ + 1)R_i
$$

- Adding liquidity in asset $i$ should keep the ratio of assets per shares constant. We round so as to not decrease the assets per share of asset $i$, $\frac{R_i}{S_i}$; that is, we favor the other LPs over the LP currently adding liquidity, to avoid any potential exploit. This means, $\frac{R_i^+}{S_i^+}\geq \frac{R_i}{S_i}$, so

$$
R_i (S_i^+ + 1) \geq R_i^+ S_i \geq R_i S_i^+
$$

- Adding liquidity needs to respect weight caps. That is,

$$
\omega_iQ^+ \geq Q_i^+
$$

### Withdraw liquidity

- Withdraw liquidity should respect price $\frac{Q_i}{R_i}$. This means $\frac{Q_i}{R_i} = \frac{Q_i^+}{R_i^+}$, or $Q_i R_i^+ = Q_i^+ R_i$. Allowing for rounding error, we must check

$$
(Q_i^+ - 1)R_i \leq Q_i R_i^+ \leq (Q_i^+ + 1)R_i
$$

- Withdraw liquidity in asset $i$ should keep the ratio of assets per shares constant. We round so as to not decrease the assets per share of asset $i$, $\frac{R_i}{S_i}$; that is, we favor the other LPs over the LP currently withdrawing liquidity, to avoid any potential exploit. This means $\frac{R_i^+}{S_i^+}\geq \frac{R_i}{S_i}$, so

$$
R_i (S_i^+ + 1) \geq R_i^+ S_i \geq R_i S_i^+
$$