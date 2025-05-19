package types

type VerifiableShare struct {
	Data         string `json:"data"`
	EphemeralKey string `json:"ephemeralKey"`
	Commitment   string `json:"commitment"`
}

type Recipient struct {
	Name      string `json:"name"`
	PublicKey string `json:"publicKey"`
}

type Challenge struct {
	EphemeralPrivateKey []byte
	EphemeralPublicKey  []byte
	Token               []byte
	Nonce               []byte
}

type ChallengeAuth struct {
	Nonce          string `json:"nonce"`
	EncryptedToken string `json:"encryptedToken"`
}

type DisclosureRequest struct {
	ID              string          `json:"id"`
	Recipient       string          `json:"recipient"`
	VerifiableShare VerifiableShare `json:"verifiableShare"`
}

type InboxChallengeResponse struct {
	Token     string `json:"token"`
	PublicKey string `json:"publicKey"`
	Nonce     string `json:"nonce"`
}

type InboxResponse struct {
	ID              string          `json:"id"`
	Org             string          `json:"org"`
	VerifiableShare VerifiableShare `json:"verifiableShare"`
}
