package elstack

// ElConfig holds Emotion Link configuration propagated from CLI flags.
type ELConfig struct {
	Use      bool
	CertPath string
	Cert     string

	// configs for VC (contents, not file paths)
	VC           string
	VCPrivKey    string
	IssuerPubkey string

	// configs of EL-Server
	Host        string
	Port        string
	AntiOverlap string
}
