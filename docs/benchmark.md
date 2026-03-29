# Benchmark Guide

Use `scripts/benchmark.sh` to generate a quick profile-comparison snapshot.

```bash
chmod +x scripts/benchmark.sh
scripts/benchmark.sh example.com ./macaron benchmark.md
```

The script runs passive, balanced, and aggressive profiles and records wall-clock duration.

Recommended:
- run each profile 3 times
- use median duration
- run on the same network and host
