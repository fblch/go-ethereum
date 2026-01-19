package elstack

// ElConfig holds Emotion Link configuration propagated from CLI flags.
type ELConfig struct {
	Use          bool
	CertPath     string

	// configs for accout-password
	Account      string
	Password     string

	// configs for VC 
	VC           string
	VCPrivKey    string
	IssuerPubkey string

	// configs of EL-Server
	Host         string
	Port         string
	AntiOverlap  string
}
