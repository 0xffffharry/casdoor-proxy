package casdoor_proxy

import (
	"casdoor-proxy/option"
	"casdoor-proxy/pkg/log"
	"casdoor-proxy/proxy"
	"context"
	"encoding/json"
	"github.com/spf13/cobra"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
)

var mainCommand = &cobra.Command{
	Use:   "casdoor-proxy",
	Short: "casdoor-proxy",
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(run())
	},
}

func Execute() {
	mainCommand.Execute()
}

var (
	paramConfig   string
	defaultLogger log.LoggerInterface
)

func init() {
	mainCommand.PersistentFlags().StringVarP(&paramConfig, "config", "c", "config.json", "config file")
	defaultLogger = log.NewLogger(os.Stdout, os.Stderr)
}

func run() int {
	configContent, err := os.ReadFile(paramConfig)
	if err != nil {
		defaultLogger.Fatalf("read config file error: %s", err.Error())
		return 1
	}

	var opt option.Option
	err = json.Unmarshal(configContent, &opt)
	if err != nil {
		defaultLogger.Fatalf("parse config file error: %s", err.Error())
		return 1
	}

	err = option.CheckOption(&opt)
	if err != nil {
		defaultLogger.Fatalf("check config error: %s", err.Error())
		return 1
	}

	var (
		output    = os.Stdout
		errOutput = os.Stderr
	)

	if opt.LogOption.Output != "" {
		f, err := os.OpenFile(opt.LogOption.Output, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o666)
		if err != nil {
			defaultLogger.Fatalf("open log file error: %s", err.Error())
			return 1
		}
		defer f.Close()
		output = f
		errOutput = f
	}

	logger := log.NewLogger(output, errOutput).SetDebug(opt.LogOption.Debug)

	if opt.LogOption.DisableTime {
		logger.DisableTime()
	}

	logger.Info("casdoor-proxy start")
	defer logger.Info("casdoor-proxy stop")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go handlerSignal(cancel, logger)

	hErr := atomic.Bool{}
	wg := sync.WaitGroup{}
	for _, proxyOption := range opt.ProxyOptions {
		wg.Add(1)
		go func(option option.ProxyOption) {
			defer wg.Done()
			err := proxy.NewProxy(ctx, logger.NewTagLogger(option.Tag), option).Run()
			if err != nil {
				hErr.Store(true)
			}
		}(proxyOption)
	}
	wg.Wait()

	if !hErr.Load() {
		return 1
	}
	return 0
}

func handlerSignal(cancel context.CancelFunc, logger log.LoggerInterface) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	sn := <-c
	logger.Warnf("receive signal: %s, stop", sn.String())
	cancel()
}
