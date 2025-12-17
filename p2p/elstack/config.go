package elstack

// ElConfig holds Emotion Link configuration propagated from CLI flags.
type ElConfig struct {
	UseEl           bool
	CertPath        string
	AccountName     string
	AccountPassword string
	VpnHost         string
	VpnServ         string
	AntiOverlap     string
}
