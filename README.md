# cf-best-ip

Cloudflare best IP optimizer with TCP prefilter and TLS/HTTP probing.

## Install

```bash
pip install cf-best-ip
```

## Usage

```bash
cf-best-ip --count 2048 --top 16
cf-best-ip --ports 443,2053,2083,2087,2096,8443
cf-best-ip --output bestip.txt
```
