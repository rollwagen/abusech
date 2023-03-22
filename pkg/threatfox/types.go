package threatfox

import (
	"strings"
	"time"
)

// IOC indicator of compromise details returned by 'query' API call
type IOC struct {
	ConfidenceLevel int `json:"confidence_level"`
	// FirstSeen       string   `json:"first_seen"`
	FirstSeen        TimeSeen `json:"first_seen"`
	ID               string   `json:"id"`
	Ioc              string   `json:"ioc"`
	IocType          string   `json:"ioc_type"`
	IocTypeDesc      string   `json:"ioc_type_desc"`
	LastSeen         *string  `json:"last_seen"`
	Malware          string   `json:"malware"`
	MalwareAlias     *string  `json:"malware_alias"`
	MalwareMalpedia  string   `json:"malware_malpedia"`
	MalwarePrintable string   `json:"malware_printable"`
	Reference        *string  `json:"reference"`
	Reporter         string   `json:"reporter"`
	Tags             []string `json:"tags"`
	ThreatType       string   `json:"threat_type"`
	ThreatTypeDesc   string   `json:"threat_type_desc"`
}

type TimeSeen time.Time

func (s *TimeSeen) UnmarshalJSON(b []byte) error {
	value := strings.Trim(string(b), `"`) // get rid of "
	if value == "" || value == "null" {
		return nil
	}

	t, err := time.Parse("2006-01-02 15:04:05 UTC", value) // parse time
	if err != nil {
		return err
	}
	*s = TimeSeen(t) // set result using the pointer
	return nil
}

func (s TimeSeen) MarshalJSON() ([]byte, error) {
	return []byte(`"` + time.Time(s).Format("2006-01-02 15:04:05 UTC") + `"`), nil
}

type IOCs struct {
	Data        []IOC  `json:"data"`
	QueryStatus string `json:"query_status"`
}

// curl -X POST https://threatfox-api.abuse.ch/api/v1/ -d '{ "query": "types" }' | jq

type IOCType struct {
	Description  string `json:"description"`
	FKThreatType string `json:"fk_threat_type"`
	Type         string `json:"ioc_type"`
}

type IOCDetail struct {
	Comment         *string `json:"comment"`
	ConfidenceLevel int     `json:"confidence_level"`
	Credits         []struct {
		CreditsAmount any    `json:"credits_amount"`
		CreditsFrom   string `json:"credits_from"`
	} `json:"credits"`
	FirstSeen        TimeSeen `json:"first_seen"`
	ID               string   `json:"id"`
	Ioc              string   `json:"ioc"`
	IocType          string   `json:"ioc_type"`
	IocTypeDesc      string   `json:"ioc_type_desc"`
	LastSeen         *string  `json:"last_seen"`
	Malware          string   `json:"malware"`
	MalwareAlias     *string  `json:"malware_alias"`
	MalwareMalpedia  string   `json:"malware_malpedia"`
	MalwarePrintable string   `json:"malware_printable"`
	MalwareSamples   []struct {
		MalwareBazaar string `json:"malware_bazaar"`
		Md5Hash       string `json:"md5_hash"`
		Sha256Hash    string `json:"sha256_hash"`
		TimeStamp     string `json:"time_stamp"`
	} `json:"malware_samples"`
	Reference      *string  `json:"reference"`
	Reporter       string   `json:"reporter"`
	Tags           []string `json:"tags"`
	ThreatType     string   `json:"threat_type"`
	ThreatTypeDesc string   `json:"threat_type_desc"`
}
