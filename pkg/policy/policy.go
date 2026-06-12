package policy

// Policy is the domain filtering policy accepted by the control API.
type Policy struct {
	Allowed   []string `json:"allowed,omitempty"`
	Denied    []string `json:"denied,omitempty"`
	CountMode bool     `json:"count_mode,omitempty"`
}

// Store persists policy updates made through the control API.
type Store interface {
	Save(Policy) error
}
