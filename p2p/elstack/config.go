package elstack

// ElConfig holds Emotion Link configuration propagated from CLI flags.
type ELConfig struct {
	Use  bool
	Cert string

	// configs for VC (contents, not file paths)
	VC           string
	VCPrivKey    string
	IssuerPubkey string

	// configs of EL-Server
	Host        string
	Port        string
	AntiOverlap string
}

func ClearELMobileConfig(
	use *bool,
	cert *string,
	vc *string,
	vcPrivkey *string,
	issuerPubkey *string,
	host *string,
	port *int,
	antiOverlap *string,
) {
	if use != nil {
		*use = false
	}
	if cert != nil {
		*cert = ""
	}
	if vc != nil {
		*vc = ""
	}
	if vcPrivkey != nil {
		*vcPrivkey = ""
	}
	if issuerPubkey != nil {
		*issuerPubkey = ""
	}
	if host != nil {
		*host = ""
	}
	if port != nil {
		*port = 0
	}
	if antiOverlap != nil {
		*antiOverlap = ""
	}
}
