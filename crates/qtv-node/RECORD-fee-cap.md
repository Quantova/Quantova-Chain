# The fee cap, what is enforced and what is not

This records the fee model as it stands in code, the band the founder settled, the
safety holes closed, and the one property that cannot be enforced in the chain
without a decision the founder has to make. It exists so no one reads the doc
comment on the charge path and believes a guarantee the chain does not deliver.

## The band

Every transaction fee falls in a band from five hundredths of a cent to one tenth
of a cent, USD 0.0005 to USD 0.0010, five hundred to one thousand dollar micro
units. A transfer sits at the floor when traffic is light and rises toward the
ceiling under contention, never above the ceiling at any load. This is the figure
the founder settled. It replaces two that disagreed, the spec which read a
hundredth to a tenth of a cent and the explorer mirror which read five to ten
cents, and all three now hold the settled band, the fee module in code, the
economics spec, and the explorer mirror.

## What was closed

The charge path ran on every transaction and could take the chain down two ways.
A rate small enough overflowed the native word on the multiply and panicked, the
same shape of fault as the slot budget. A rate of zero divided by zero. Both are
gone. The multiply saturates and the divide is checked, so an extreme or
misconfigured rate yields the largest representable charge or zero rather than
aborting the block, and the genesis loader now rejects a zero rate, a zero native
unit, and a schedule that rounds a transfer fee to nothing, so the misconfiguration
is caught at load rather than at the first block.

## The claim, in the words we may actually use

Read this before writing any sentence about the fee, because it changes what we may
claim. The fee is capped in QTOV and targeted in USD, and the peg is maintained by
governance. It is not capped at a tenth of a cent. That last sentence would require
reading the true price of QTOV at charge time, a live feed the chain refuses because
a feed anyone can manipulate would undo the whole case the chain is built on, that
nothing outside can break us. We made classical cryptography uncompilable so no
outside thing could break us, and an oracle is an outside thing. So we do not have
it, and we do not claim the property that needs it.

## The native ceiling, chosen and built

The enforced cap is a hard native ceiling, a maximum number of base units a fee can
ever be, set in genesis as fee_max_native, folded into the genesis hash, and
independent of the rate. The charge is clamped to it after the band conversion, so
no rate however stale drives a fee past it in the unit the sender actually pays. The
dollar band is the target the governance rate is held to, on a controlled cadence
and a bounded step, never from a live feed.

The residual, stated loudly because it decides what we may say. A native ceiling
bounds base units, not dollars. If QTOV rises faster than governance re-pegs the
rate, the realized dollar cost of a fixed native ceiling drifts above the target,
because the same base units are worth more at a price the chain does not observe. It
drifts cheaper when QTOV falls faster than governance lowers the rate. This is
inherent to a chain with no price feed and it is chosen deliberately, in exchange
for depending on no outside feed. The honest line is capped in QTOV, targeted in
USD, peg held by governance, and never capped at a tenth of a cent in dollars.

## Congestion and the free bid

The free bid is fixed. The charge is now what you bid, clamped to the band, so a
higher declared fee orders a transaction earlier and is charged for it up to the
ceiling. A bid is no longer free below the ceiling, so a sender no longer bids the
maximum for nothing, and ordering no longer collapses to the tiebreak under load.
This is built in the charge path.

Above the ceiling the charge pins to the band, so it cannot ration further without
escaping the band, which the cap forbids. The lever past that point is the meter,
required meter under contention, a compute cost to be admitted when blocks are full,
which rations by work and not by the dollar charge and so holds the band. That is
the near term saturation lever and it is not yet built.

The destination is stake weighted priority. It is the right lever because it is
sybil resistant, a seat at the front costs real bonded stake rather than a free
declaration or a burst of compute anyone can spend. It is named here so that when
bonded staking lands, which it has not, no one has to rediscover that this is where
congestion ordering was always meant to go. Until then the meter is the interim
lever and pay what you bid is the floor beneath it.

There is a residual tension and it is recorded rather than hidden. A fee capped in
dollars cannot also price ration block space at true saturation, because price
rationing needs a fee that rises without bound and the cap forbids that. So at
saturation the rationing is not the dollar charge but the meter and, in time, stake.
The cap and the anti spam property meet inside the band and hand off to a non dollar
lever above it, rather than being in contradiction.
