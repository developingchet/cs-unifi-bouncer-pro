package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// --- Traffic Matching Lists (integration v1) ---------------------------------

func listTMLs(ctx context.Context, c *unifiClient, siteID string) ([]TrafficMatchingList, error) {
	if err := requireSegment("site ID", siteID); err != nil {
		return nil, err
	}
	endpointURL := c.networkURL("/integration/v1/sites/%s/traffic-matching-lists", siteID)
	data, err := listAllV1Pages(ctx, c, endpointURL, "list-tmls")
	if err != nil {
		return nil, err
	}
	out := make([]TrafficMatchingList, 0, len(data))
	for _, raw := range data {
		var t apiTMLV1Listed
		if err := json.Unmarshal(raw, &t); err != nil {
			continue
		}
		out = append(out, t.model())
	}
	return out, nil
}

func createTML(ctx context.Context, c *unifiClient, siteID string, list TrafficMatchingList) (TrafficMatchingList, error) {
	if err := requireSegment("site ID", siteID); err != nil {
		return TrafficMatchingList{}, err
	}
	endpointURL := c.networkURL("/integration/v1/sites/%s/traffic-matching-lists", siteID)
	raw, err := doPOSTv2(ctx, c, endpointURL, "create-tml", tmlToWire(list))
	if err != nil {
		return TrafficMatchingList{}, err
	}
	var created apiTMLV1Listed
	if err := json.Unmarshal(raw, &created); err != nil {
		return TrafficMatchingList{}, fmt.Errorf("decode created TML: %w", err)
	}
	return created.model(), nil
}

func updateTML(ctx context.Context, c *unifiClient, siteID string, list TrafficMatchingList) error {
	if err := requireSegments("site ID", siteID, "traffic matching list ID", list.ID); err != nil {
		return err
	}
	endpointURL := c.networkURL("/integration/v1/sites/%s/traffic-matching-lists/%s", siteID, list.ID)
	return doPUT(ctx, c, endpointURL, "update-tml", tmlToWireUpdate(list))
}

func deleteTML(ctx context.Context, c *unifiClient, siteID, id string) error {
	if err := requireSegments("site ID", siteID, "traffic matching list ID", id); err != nil {
		return err
	}
	endpointURL := c.networkURL("/integration/v1/sites/%s/traffic-matching-lists/%s", siteID, id)
	return confirmDeleted(doDELETE(ctx, c, endpointURL, "delete-tml"), "traffic matching list "+id, func() (bool, error) {
		return v1CollectionHasID(ctx, c, c.networkURL("/integration/v1/sites/%s/traffic-matching-lists", siteID), "list-tmls", id)
	})
}

func tmlItemToWire(item TrafficMatchingListItem) apiTMLItemV1 {
	t := item.Type
	if t == "" {
		// Fallback to inference if Type is not set
		t = "IP_ADDRESS"
		if strings.Contains(item.Value, "/") {
			t = "SUBNET"
		}
	}
	if t == "PORT_NUMBER" {
		if n, err := strconv.Atoi(item.Value); err == nil {
			return apiTMLItemV1{Type: t, Value: n}
		}
	}
	return apiTMLItemV1{Type: t, Value: item.Value}
}

func tmlItemsToWire(list TrafficMatchingList) []apiTMLItemV1 {
	items := make([]apiTMLItemV1, 0, len(list.Items))
	for _, item := range list.Items {
		items = append(items, tmlItemToWire(item))
	}
	return items
}

func tmlToWire(list TrafficMatchingList) apiTMLV1 {
	return apiTMLV1{ID: list.ID, Type: list.Type, Name: list.Name, Items: tmlItemsToWire(list)}
}

func tmlToWireUpdate(list TrafficMatchingList) apiTMLV1Update {
	return apiTMLV1Update{Type: list.Type, Name: list.Name, Items: tmlItemsToWire(list)}
}
