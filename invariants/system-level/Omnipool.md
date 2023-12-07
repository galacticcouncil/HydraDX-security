# System Level

### Notation

| Variable     | Description                             |
|--------------|-----------------------------------------|
| $Q$          | Total LRNA in Omnipool                  |
| $Q_i$        | LRNA in subpool for asset $i$           |
| $S_i$        | Shares in asset $i$ subpool             |
| $B_i$        | Protocol shares in asset $i$            |
| $s_i^\alpha$ | Shares in asset $i$ held by LP $\alpha$ |
For a given state variable $X$, we will generally denote the value of $X$ *after* the operation by $X^+$.

[Omnipool Specification](https://github.com/galacticcouncil/HydraDX-simulations/blob/main/hydradx/spec/OmnipoolSpec.ipynb)

- Total shares issued should equal the sum of shares held in all LP positions and protocol.

$$
S_i = \sum_{\alpha}s_i^\alpha + B_i
$$

- The total LRNA in Omnipool should equal the sum of LRNA held by pools.

$$
Q = \sum_i Q_i
$$