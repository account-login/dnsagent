python -m dnsagent.scripts.benchmark --process 1
python -m dnsagent.scripts.benchmark --process 2
python -m dnsagent.scripts.benchmark --process 3
python -m dnsagent.scripts.benchmark --process 2 --tcp-only
python -m dnsagent.scripts.benchmark --process 2 --tcp-only --no-reuse-resolver --concurrency 50 --count 2000
python -m dnsagent.scripts.benchmark --process 2 --tcp-only --no-reuse-resolver --concurrency 100 --count 2000
