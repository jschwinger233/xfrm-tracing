package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"

	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

var (
	pcapFilter string

	pwruBuf     = make(map[string][]string)
	skbConsumed = make(map[string]bool)
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	tcCh, ctx, err := watchTc(ctx)
	if err != nil {
		log.Fatalf("Failed to watch tc: %+v", err)
	}

	xfrmCh, ctx, err := watchXfrm(ctx)
	if err != nil {
		log.Fatalf("Failed to watch xfrm: %+v", err)
	}

	pwruCh, ctx, err := watchPwru(ctx)
	if err != nil {
		log.Fatalf("Failed to watch pwru: %+v", err)
	}

	for {
		select {
		case tcMsg := <-tcCh:
			fmt.Printf("tc: %s\n", tcMsg)
		case xfrmMsg := <-xfrmCh:
			fmt.Printf("xfrm: %s\n", xfrmMsg)
		case pwruMsg := <-pwruCh:
			fmt.Printf("pwru: %s\n", pwruMsg)
		case <-ctx.Done():
			return
		}
	}
}

func watch(ctx context.Context, cmd []string, lineHandle func(string) (string, bool)) (<-chan string, context.Context, error) {
	command := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := command.Start(); err != nil {
		return nil, nil, err
	}

	ch := make(chan string)
	retCtx, cancel := context.WithCancel(context.Background())
	go func() {
		defer cancel()
		//defer close(ch)
		defer command.Wait()
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line, ok := lineHandle(scanner.Text())
			if ok {
				ch <- line
			}
		}
		if err := scanner.Err(); err != nil {
			log.Printf("Scan error: %+v", err)
		}
	}()
	return ch, retCtx, nil
}

func watchTc(ctx context.Context) (<-chan string, context.Context, error) {
	return watch(ctx, []string{"tc", "monitor"}, func(line string) (string, bool) {
		return line, true
	})
}

func watchXfrm(ctx context.Context) (<-chan string, context.Context, error) {
	return watch(ctx, []string{"ip", "xfrm", "monitor", "SA", "policy"}, func(line string) (string, bool) {
		return line, true
	})
}

func watchPwru(ctx context.Context) (<-chan string, context.Context, error) {
	nsID, err := currentNetns()
	if err != nil {
		return nil, nil, err
	}
	ns := strconv.FormatUint(nsID, 10)
	return watch(ctx, []string{"pwru", "--filter-track-skb", "--output-meta", "--output-tuple", "--filter-netns", ns, pcapFilter},
		func(line string) (string, bool) {
			parts := strings.Split(line, " ")
			skb := parts[0]
			skbNs := ""
			for _, part := range parts {
				if strings.HasPrefix(part, "netns=") {
					skbNs = strings.TrimPrefix(part, "netns=")
				}
			}

			pwruBuf[skb] = append(pwruBuf[skb], line)

			if strings.Contains(line, "kfree_skbmem") {
				defer delete(skbConsumed, skb)
				defer delete(pwruBuf, skb)
				if !skbConsumed[skb] && skbNs == ns {
					return strings.Join(pwruBuf[skb], "\n"), true
				}
			}

			if strings.Contains(line, "consume_skb") {
				skbConsumed[skb] = true
			}
			return "", false
		})
}

func currentNetns() (uint64, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ns, err := netns.Get()
	if err != nil {
		return 0, err
	}
	defer ns.Close()
	var s unix.Stat_t
	if err := unix.Fstat(int(ns), &s); err != nil {
		return 0, err
	}
	return s.Ino, nil
}
