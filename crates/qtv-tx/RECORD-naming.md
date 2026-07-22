Why the transaction body names what it names

This records the naming of the metering field, the fee, and the call, and the reasoning
behind each, so the next person building against this surface does not reach for a
borrowed word and quietly inherit its assumption.

The meter and the fee are two things, and gas was one word hiding it.

Fee is the floor and the bid. It is ours and it is correctly named. The meter is real,
per operation, weighted, and it computes what it spent and then discards it for charging.
Ethereum fuses meter and price. We split them before we noticed. The borrowed word was
hiding exactly that, our meter does not pay. This is the clearest statement of what our
fee model actually is, and it is why the USD cap is coherent. The charge is a fixed
protocol fee, dollar denominated, capped at a tenth of a cent, and the cap binds because
the charge is fixed and decoupled from how much the meter ran. A bid above the floor
orders a transaction earlier in the pool and never changes what is paid.

So the transaction carries both, already separate. The fee field is the floor and the
bid. The meter field is the ceiling on execution work the machine meters and halts at,
and it never prices.

The name is Q_Meter, field meter_limit. It says what it is and points at fee for what you
pay, which is the whole distinction we found.

The candidates that were rejected, and why, because the next person will reach for one of
them. Q_Cost re-imports the exact conflation we are removing, a cost is a charge. Q_Steps
implies one unit per instruction, and our meter is weighted, 1210 over eleven
instructions rather than eleven. Q_Fuel is a borrowed word too. Qgas on the
mechanism is Ethereum's model with our prefix on it, which hides the inheritance rather
than announcing it and is worse than the borrowed word itself.

Qgas is the denomination, the smallest unit of QTOV where Ethereum says wei. Balances and
the fee are denominated in it. That is a unit and it is ours. It does not go on the
mechanism.

The call shape is inherited and accepted deliberately. A transaction wraps a transfer as
a call with a target and args. That is Ethereum's model, where every transaction is a
call to an address with calldata. Today nothing is ever called, a call is always a native
transfer, the target is the recipient, the args are eight bytes of amount, and the only
program that runs is the fixed transfer. So the name is inherited. It is kept anyway,
knowingly, because contracts are coming, asset lowering is coming, the SEND opcode already
exists in the machine, and modelling a transfer as recipient and amount now would mean
changing the transaction format again when they land, which is the thing we do not do. The
name is inherited and the shape is where we are going. It is recorded here as noticed and
accepted, not missed.

The standing rule this came from. Sweep every interface for borrowed names before freezing
it. A borrowed name carries a borrowed assumption and every client that reads it inherits
the assumption, which is the same reason we refused to wrap our chain in another chain's
interface.
