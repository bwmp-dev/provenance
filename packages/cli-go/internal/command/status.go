package command

import (
	"context"
	"encoding/json"
	"net/url"
)

func (a App) status(ctx context.Context, api *api, id string) error {
	root := "/v1/release-candidates/" + url.PathEscape(id)
	candidate, e := api.call(ctx, "GET", root, nil, false)
	if e != nil || candidate.status != 200 || text(candidate.body, "id") != id {
		return ErrFailed
	}
	summary := map[string]any{"candidateId": id, "state": text(candidate.body, "state")}
	if summary["state"] == "" {
		return ErrFailed
	}
	for _, kind := range []string{"executions", "events"} {
		items := []any{}
		cursor := ""
		seen := map[string]bool{}
		for pages := 0; ; pages++ {
			if pages >= 100 {
				return ErrFailed
			}
			path := root + "/" + kind + "?limit=100"
			if cursor != "" {
				path += "&cursor=" + url.QueryEscape(cursor)
			}
			page, e := api.call(ctx, "GET", path, nil, false)
			if e != nil || page.status != 200 {
				return ErrFailed
			}
			rows, ok := page.body["items"].([]any)
			if !ok || len(rows) > 100 {
				return ErrFailed
			}
			for _, row := range rows {
				m, ok := row.(map[string]any)
				if !ok {
					return ErrFailed
				}
				out := map[string]string{}
				for _, key := range []string{"id", "state", "kind", "occurredAt", "createdAt", "matrixEntryId"} {
					if s := text(m, key); s != "" {
						out[key] = s
					}
				}
				items = append(items, out)
			}
			info, ok := page.body["page"].(map[string]any)
			if !ok {
				return ErrFailed
			}
			more, ok := info["hasMore"].(bool)
			if !ok {
				return ErrFailed
			}
			if !more {
				break
			}
			cursor = text(info, "nextCursor")
			if cursor == "" || len(cursor) > 2048 || seen[cursor] {
				return ErrFailed
			}
			seen[cursor] = true
		}
		summary[kind] = items
	}
	return json.NewEncoder(a.Out).Encode(summary)
}
