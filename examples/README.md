# pyasn1 examples

This directory contains runnable example scripts demonstrating pyasn1
features, including advanced and obscure use cases.

## Running

Sync the development environment, then run the examples directly:

```bash
uv sync
uv run python examples/simple_sequence.py
uv run python examples/open_type.py
uv run python examples/constraints.py
uv run python examples/recursive_sequence.py
uv run python examples/round_trip.py
```

No external dependencies are required beyond pyasn1 itself.
