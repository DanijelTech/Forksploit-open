# Producer

> **⚠️ USE AT YOUR OWN RISK — THE AUTHORS ACCEPT NO LIABILITY.**
> **ForkSploit is provided "AS IS", without warranty of any kind. It signs and
> sends real transactions and can move real funds. You use it entirely at your
> own risk and under your own full responsibility; the authors and copyright
> holders accept NO liability whatsoever for any consequences of its use, misuse
> or inability to use it.**

The producer is the component that is responsible for producing information used by oracles.

### Lifecycle

Transactions finished execution  
=> `Producer.produce` is called (generates data)  
=> All `Oracle.oracle`s are called   
=> `Producer.notify_end` is called (remove cache)
