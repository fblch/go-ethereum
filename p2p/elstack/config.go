package elstack

// ElConfig holds Emotion Link configuration propagated from CLI flags.
type ELConfig struct {
	UseEl           bool
	CertPath        string
	Account     string
	Password string
	Host         string
	Port         string
	AntiOverlap     string
}
