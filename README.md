# xfrm-tracing
```
docker run -it --rm --net host -v /sys/kernel/debug:/sys/kernel/debug --privileged uumg/xfrm-tracing xfrm-tracing 'esp or (tcp and dst port 8000)'
```
