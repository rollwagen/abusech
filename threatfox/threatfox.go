// Package threatfox provides convenience methods to access the threatfox.abuse.ch API
package threatfox

import (
	"encoding/json"
	"fmt"
	"strconv"

	resty "github.com/go-resty/resty/v2"
	"github.com/samber/lo"
)

const baseURL = "https://threatfox-api.abuse.ch/api/v1/"

type ThreatFox struct {
	client *resty.Client
}

func New() *ThreatFox {
	return &ThreatFox{
		client: resty.New(),
	}
}

// GetIOCByID queries ThreatFox for a particular IOC id sending an HTTP POST request to the Threatfox API
func (t *ThreatFox) GetIOCByID(id string) (IOCDetail, error) {
	_, err := strconv.Atoi(id)
	if err != nil {
		return IOCDetail{}, fmt.Errorf("id is expected to be a number")
	}

	body := fmt.Sprintf("{ \"query\": \"ioc\", \"id\": %s }", id)

	resp, err := t.client.R().
		SetHeader("Content-Type", "application/json").
		SetBody([]byte(body)).
		SetResult(IOCDetail{}).
		Post(baseURL)
	if err != nil {
		return IOCDetail{}, fmt.Errorf("could not complete http POST to %s: %w", baseURL, err)
	}

	r := resp.Result()
	if iocDetail, ok := r.(*IOCDetail); ok {
		return *iocDetail, nil
	}

	return IOCDetail{}, fmt.Errorf("could not type cast response to IOCDetail")
}

// SearchIOC searches IOC for the given term
func (t *ThreatFox) SearchIOC(term string) ([]IOC, error) {
	if len(term) < 3 {
		return nil, fmt.Errorf("please provide a search term with a minimum length of 3 characters")
	}
	body := fmt.Sprintf("{ \"query\": \"search_ioc\", \"search_term\": \"%s\" }", term)

	resp, err := t.client.R().
		SetHeader("Content-Type", "application/json").
		SetBody([]byte(body)).
		SetResult(IOCs{}).
		Post(baseURL)
	if err != nil {
		return nil, fmt.Errorf("could not complete http POST to %s: %w", baseURL, err)
	}

	r := resp.Result().(*IOCs)

	return r.Data, nil
}

// GetIOCs return a copy of the current IOC dataset from ThreatFox by sending an HTTP POST request to the Threatfox API
func (t *ThreatFox) GetIOCs(days int) ([]IOC, error) {
	if days < 1 || days > 7 {
		return nil, fmt.Errorf("number of days outside range min=1 max=7: %d", days)
	}
	body := fmt.Sprintf("{ \"query\": \"get_iocs\", \"days\": %d }", days)

	resp, err := t.client.R().
		SetHeader("Content-Type", "application/json").
		SetBody([]byte(body)).
		SetResult(IOCs{}).
		Post(baseURL)
	if err != nil {
		return nil, fmt.Errorf("could not complete http POST to %s: %w", baseURL, err)
	}

	r := resp.Result().(*IOCs)

	return r.Data, nil
}

// GetIOCTypes obtains a list of supported IOC / threat types from ThreatFox
func (t *ThreatFox) GetIOCTypes() ([]IOCType, error) {
	resp, err := t.client.R().
		SetHeader("Content-Type", "application/json").
		SetBody([]byte(`{ "query": "types" }`)).
		Post(baseURL)
	if err != nil {
		panic(err)
	}

	jsonMap := map[string]any{} // the map for JSON

	err = json.Unmarshal(resp.Body(), &jsonMap)
	if err != nil {
		panic(err)
	}

	data, ok := jsonMap["data"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("response is missing required json object 'data'")
	}

	var types []IOCType

	for key, val := range data {

		_, err := strconv.Atoi(key)
		if err != nil { // ioc type ids are numbers (positive integers)
			panic(err)
		}

		object, _ := val.(map[string]any)

		types = append(types, IOCType{
			object["description"].(string),
			object["fk_threat_type"].(string),
			object["ioc_type"].(string),
		})
	}

	return types, nil
}

func (t *ThreatFox) IsValidIOCType(iocType string) (bool, error) {
	types, _ := t.GetIOCTypes()
	valid := lo.ContainsBy(types, func(t IOCType) bool {
		return t.Type == iocType
	})
	if !valid {
		return false, fmt.Errorf("'%s' is not a valid ioc type; valid types are %v", iocType,
			lo.Map(types, func(t IOCType, index int) string {
				return t.Type
			}))
	}
	return true, nil
}
