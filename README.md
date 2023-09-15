# xfrm-tracing

An eBPF tool for tracing [XFRM errors](https://docs.kernel.org/networking/xfrm_proc.html).

## Usage

1. Run `kubectl create -f https://raw.githubusercontent.com/jschwinger233/xfrm-tracing/main/xfrm-tracing.ds.yaml` to deploy an `xfrm-tracing` pod on each node.
2. Wait until you see logs like `Attached 505/720 kprobes` in the stdout of the xfrm-tracing pods.
3. Operate your cluster.
4. If any counter in `/proc/net/xfrm_stat` increases, find `++` signs from xfrm-tracing pods' stdout.

## Example Output

First let's dump tracing logs from an xfrm-tracing pod:

```
kubectl logs xfrm-tracing-tltzx > xfrm-tracing-tltzx.log
```

Then search `++` from log file, find the first match:

```
2023-09-15 15:03:46.261062368 +0000 UTC m=+1300.131558595	XfrmInNoStates++: mark=0xd00 if=2(eth0) IPv4=192.168.112.29>192.168.139.255 IPSecESP=spi:3,seq:3
```

It's `XfrmInNoStates`. Then let's check what happened before this by searching dest IP `192.168.139.255`:

```
2023-09-15 14:47:48.282473501 +0000 UTC m=+342.152969726	Deleted src 0.0.0.0 dst 192.168.139.255
2023-09-15 14:47:48.28252585 +0000 UTC m=+342.153022280		proto esp spi 0x00000003 reqid 1 mode tunnel
2023-09-15 14:47:48.282589496 +0000 UTC m=+342.153085723		replay-window 0
2023-09-15 14:47:48.282642566 +0000 UTC m=+342.153138791		mark 0xd00/0xf00 output-mark 0x0/0xf00
2023-09-15 14:47:48.282697726 +0000 UTC m=+342.153193951		aead rfc4106(gcm(aes)) 0x1aa4ac06e925dc94315ece4d18cd0ef36023fd3e 128
2023-09-15 14:47:48.28275114 +0000 UTC m=+342.153247368		anti-replay context: seq 0x0, oseq 0x0, bitmap 0x00000000
2023-09-15 14:47:48.282816263 +0000 UTC m=+342.153312488		sel src 0.0.0.0/0 dst 0.0.0.0/0
```

We see an XFRM state delete event. This could explain the `XfrmInNoStates`: no XFRM state matches ingress skb with dest IP 192.168.139.255 afterwards.

To confirm our theory, let's find new XFRM states installed between the above deletion and first `XfrmInNoStates`. By searching `mark 0xd00`, we have the only XFRM state update event:

```
2023-09-15 14:47:48.28358601 +0000 UTC m=+342.154082240	src 0.0.0.0 dst 192.168.60.90
2023-09-15 14:47:48.283640207 +0000 UTC m=+342.154136427		proto esp spi 0x00000003 reqid 1 mode tunnel
2023-09-15 14:47:48.283693748 +0000 UTC m=+342.154189975		replay-window 0
2023-09-15 14:47:48.283744051 +0000 UTC m=+342.154240277		mark 0xd00/0xf00 output-mark 0x0/0xf00
2023-09-15 14:47:48.283804773 +0000 UTC m=+342.154301003		aead rfc4106(gcm(aes)) 0x1aa4ac06e925dc94315ece4d18cd0ef36023fd3e 128
2023-09-15 14:47:48.283855949 +0000 UTC m=+342.154352171		anti-replay context: seq 0x0, oseq 0x0, bitmap 0x00000000
2023-09-15 14:47:48.283908587 +0000 UTC m=+342.154404808		sel src 0.0.0.0/0 dst 0.0.0.0/0
```

This new installed XFRM state can't handle that dropped traffic, Q.E.D.

## How it works

This tool attaches kprobe programs on all the possible positions of `XFRM_INC_STATS` to trace XFRM error events. Along with `ip xfrm monitor` and `tc monitor`, we collect all the helpful information together, trying to provide records of "what xfrm states and policies are there when an XFRM error encountered".
