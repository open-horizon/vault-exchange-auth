package plugin

import ()

type UserDefinition struct {
	Password    string `json:"password"`
	Admin       bool   `json:"admin"`
	HubAdmin    bool   `json:"hubAdmin"`
	Email       string `json:"email"`
	LastUpdated string `json:"lastUpdated,omitempty"`
}

type GetUsersResponse struct {
	Users     map[string]UserDefinition `json:"users"`
	LastIndex int                       `json:"lastIndex"`
}

type Agbot struct {
	Token         string `json:"token"`
	Name          string `json:"name"`
	Owner         string `json:"owner"`
	MsgEndPoint   string `json:"msgEndPoint"`
	LastHeartbeat string `json:"lastHeartbeat"`
	PublicKey     []byte `json:"publicKey"`
}

type GetAgbotsResponse struct {
	Agbots    map[string]Agbot `json:"agbots"`
	LastIndex int              `json:"lastIndex"`
}
