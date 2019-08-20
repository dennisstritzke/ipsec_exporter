package cmd

import (
	"fmt"
	"github.com/dennisstritzke/ipsec_exporter/exporter"
	"github.com/dennisstritzke/ipsec_exporter/ipsec"
	"github.com/spf13/cobra"
	"os"
)

const (
	flagIpsecConfigFile  = "config-path"
	flagWebListenAddress = "web.listen-address"
	flagSudo             = "enable.sudo"
)

var Version string
var RootCmd = &cobra.Command{
	Use:     "ipsec_exporter",
	Short:   "Prometheus exporter for ipsec status.",
	Long:    "",
	Run:     defaultCommand,
	Version: Version,
}

func init() {
	RootCmd.PersistentFlags().StringVar(&exporter.IpSecConfigFile, flagIpsecConfigFile,
		"/etc/ipsec.conf",
		"Path to the ipsec config file.")

	RootCmd.PersistentFlags().StringVar(&exporter.WebListenAddress, flagWebListenAddress,
		"0.0.0.0:9536",
		"Address on which to expose metrics.")
	RootCmd.PersistentFlags().BoolVar(&ipsec.UseSudo, flagSudo,
		false,
		"Executing command with sudo.")
}

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func defaultCommand(_ *cobra.Command, _ []string) {
	exporter.Serve()
}
