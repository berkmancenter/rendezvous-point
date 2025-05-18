package types

type Recipient struct {
	Name      string `json:"name"`
	PublicKey string `json:"publicKey"`
}

type DisclosureRequest struct {
	ID        string `json:"id"`
	Recipient string `json:"recipient"`
	Share     string `json:"share"`
}

type InboxChallengeResponse struct {
	Token           string `json:"token"`
	ServerPublicKey string `json:"serverPublicKey"`
}

type InboxResponse struct {
	ID    string `json:"id"`
	Org   string `json:"org"`
	Share string `json:"share"`
}

type Challenge struct {
	EphemeralPrivateKey []byte
	EphemeralPublicKey  []byte
	Token               []byte
}
