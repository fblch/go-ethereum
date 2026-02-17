package elstack

// ELConfig holds Emotion Link configuration propagated from CLI flags.
// Note: field names drop the leading EL prefix here per specification.
type ELConfig struct {
	Use           bool
	HolderVC      string
	HolderPrivKey string
	AntiOverlap   string
	IssuerPubKey  string
	ServerAddr    string
	ServerPort    int
	ServerCACert  string
	CapturePath   *string
}

func ClearELMobileConfig(
	use *bool,
	holderVC *string,
	holderPrivKey *string,
	antiOverlap *string,
	issuerPubKey *string,
	serverAddr *string,
	serverPort *int,
	serverCACert *string,
	capturePath *string,
) {
	if use != nil {
		*use = false
	}
	if holderVC != nil {
		*holderVC = ""
	}
	if holderPrivKey != nil {
		*holderPrivKey = ""
	}
	if antiOverlap != nil {
		*antiOverlap = ""
	}
	if issuerPubKey != nil {
		*issuerPubKey = ""
	}
	if serverAddr != nil {
		*serverAddr = ""
	}
	if serverPort != nil {
		*serverPort = 0
	}
	if serverCACert != nil {
		*serverCACert = ""
	}
	if capturePath != nil {
		*capturePath = ""
	}
}
