package controller

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
)

// apiTMLV1Listed is an integration v1 traffic matching list as the controller
// returns it. A shard list holds thousands of items, so item values are read
// straight into text rather than through an interface value and fmt.
type apiTMLV1Listed struct {
	ID    string             `json:"id"`
	Type  string             `json:"type"`
	Name  string             `json:"name"`
	Items []apiTMLItemListed `json:"items"`
}

type apiTMLItemListed struct {
	Type  string       `json:"type"`
	Value tmlItemValue `json:"value"`
}

// tmlItemValue is an item value as text: a string as it is, and a number (a
// port) in the shortest form that reads back as the same value.
type tmlItemValue string

func (v *tmlItemValue) UnmarshalJSON(b []byte) error {
	switch {
	case len(b) >= 2 && b[0] == '"' && bytes.IndexByte(b, '\\') < 0:
		*v = tmlItemValue(b[1 : len(b)-1])
	case len(b) > 0 && b[0] == '"':
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*v = tmlItemValue(s)
	case bytes.Equal(b, []byte("null")):
	default:
		n, err := strconv.ParseFloat(string(b), 64)
		if err != nil {
			var other any
			if err := json.Unmarshal(b, &other); err != nil {
				return err
			}
			*v = tmlItemValue(fmt.Sprint(other))
			return nil
		}
		*v = tmlItemValue(strconv.FormatFloat(n, 'g', -1, 64))
	}
	return nil
}

func (t apiTMLV1Listed) model() TrafficMatchingList {
	items := make([]TrafficMatchingListItem, len(t.Items))
	for i, item := range t.Items {
		items[i] = TrafficMatchingListItem{Type: item.Type, Value: string(item.Value)}
	}
	return TrafficMatchingList{ID: t.ID, Type: t.Type, Name: t.Name, Items: items}
}
