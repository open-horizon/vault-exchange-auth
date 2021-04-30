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