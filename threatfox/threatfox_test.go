package threatfox

import (
	"net/http"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
)

func TestTF_SearchIOC(t *testing.T) {
	tf := New()

	httpmock.ActivateNonDefault(tf.client.GetClient())
	defer httpmock.DeactivateAndReset()

	responder, err := httpmock.NewJsonResponder(http.StatusOK, httpmock.File("testdata/query_search_ioc_search_term.json"))
	if err != nil {
		t.FailNow()
	}
	httpmock.RegisterResponder("POST", baseURL, responder)

	const (
		term = "139.180.203.104"
		id   = "1337"
	)

	var result []IOC
	result, err = tf.SearchIOC(term)
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, len(result) > 0)
	assert.Equal(t, result[0].ID, id)
}

func TestTF_GetIOCByID(t *testing.T) {
	tf := New()

	httpmock.ActivateNonDefault(tf.client.GetClient())
	defer httpmock.DeactivateAndReset()

	responder, err := httpmock.NewJsonResponder(http.StatusOK, httpmock.File("testdata/query_ioc_id_1092411.json"))
	if err != nil {
		t.FailNow()
	}
	httpmock.RegisterResponder("POST", baseURL, responder)

	const id = "1092411"

	detail, err := tf.GetIOCByID(id)
	if err != nil {
		t.FailNow()
	}

	assert.Equal(t, id, detail.ID)
}
