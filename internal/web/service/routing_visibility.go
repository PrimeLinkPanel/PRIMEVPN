package service

import (
	"encoding/json"
	"os"
	"sort"
	"strings"

	"github.com/mhsanaei/PRIMEVPN/v3/internal/database"
	"github.com/mhsanaei/PRIMEVPN/v3/internal/database/model"
)

const hiddenBalancerTagsEnv = "XUI_HIDDEN_BALANCER_TAGS"

func hiddenBalancerTagRules() []string {
	raw := os.Getenv(hiddenBalancerTagsEnv)
	if strings.TrimSpace(raw) == "" {
		return nil
	}

	parts := strings.Split(raw, ",")
	rules := make([]string, 0, len(parts))

	for _, part := range parts {
		rule := strings.TrimSpace(part)
		if rule != "" {
			rules = append(rules, rule)
		}
	}

	return rules
}

func IsHiddenBalancerTag(tag string) bool {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return false
	}

	for _, rule := range hiddenBalancerTagRules() {
		if rule == tag {
			return true
		}

		if strings.HasSuffix(rule, "*") {
			prefix := strings.TrimSuffix(rule, "*")
			if prefix != "" && strings.HasPrefix(tag, prefix) {
				return true
			}
		}
	}

	return false
}

func FilterVisibleBalancerTags(tags []string) []string {
	if len(tags) == 0 || len(hiddenBalancerTagRules()) == 0 {
		return tags
	}

	visible := make([]string, 0, len(tags))
	for _, tag := range tags {
		if IsHiddenBalancerTag(tag) {
			continue
		}
		visible = append(visible, tag)
	}
	return visible
}

// IsHiddenInboundTag resolves an inbound tag through the database so newer
// route-testing endpoints cannot be used to probe hidden inbounds directly.
func IsHiddenInboundTag(tag string) bool {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return false
	}
	return hiddenInboundTags()[tag]
}

// IsHiddenRouteResult performs a JSON-shape check without coupling this
// package to a particular Xray result struct version.
func IsHiddenRouteResult(result any) bool {
	raw, err := json.Marshal(result)
	if err != nil {
		return false
	}
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		return false
	}
	outboundTag := stringFromAny(value["outboundTag"])
	if outboundTag != "" && IsHiddenOutboundTag(outboundTag) {
		return true
	}
	balancerTag := stringFromAny(value["balancerTag"])
	return balancerTag != "" && IsHiddenBalancerTag(balancerTag)
}

func hiddenInboundTags() map[string]bool {
	hidden := make(map[string]bool)

	db := database.GetDB()
	var inbounds []*model.Inbound

	if err := db.Model(model.Inbound{}).Find(&inbounds).Error; err != nil {
		return hidden
	}

	for _, inbound := range inbounds {
		if inbound == nil {
			continue
		}

		if isHiddenInbound(inbound) && strings.TrimSpace(inbound.Tag) != "" {
			hidden[inbound.Tag] = true
		}
	}

	return hidden
}

func stringFromAny(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

func stringListFromAny(v any) []string {
	switch value := v.(type) {
	case string:
		if strings.TrimSpace(value) == "" {
			return nil
		}
		return []string{strings.TrimSpace(value)}

	case []any:
		out := make([]string, 0, len(value))
		for _, item := range value {
			if s := stringFromAny(item); s != "" {
				out = append(out, s)
			}
		}
		return out

	case []string:
		out := make([]string, 0, len(value))
		for _, item := range value {
			if s := strings.TrimSpace(item); s != "" {
				out = append(out, s)
			}
		}
		return out
	}

	return nil
}

func objectTag(obj any) string {
	m, ok := obj.(map[string]any)
	if !ok {
		return ""
	}

	return stringFromAny(m["tag"])
}

func isHiddenBalancerObject(balancer any) bool {
	m, ok := balancer.(map[string]any)
	if !ok {
		return false
	}

	tag := stringFromAny(m["tag"])
	return IsHiddenBalancerTag(tag)
}

func hiddenBalancerTagsFromObjects(balancers []any) map[string]bool {
	hidden := make(map[string]bool)

	for _, balancer := range balancers {
		tag := objectTag(balancer)
		if tag == "" {
			continue
		}

		if isHiddenBalancerObject(balancer) {
			hidden[tag] = true
		}
	}

	return hidden
}

func isHiddenRoutingRule(rule any, hiddenInboundTagMap map[string]bool, hiddenBalancerTagMap map[string]bool) bool {
	m, ok := rule.(map[string]any)
	if !ok {
		return false
	}

	outboundTag := stringFromAny(m["outboundTag"])
	if outboundTag != "" && IsHiddenOutboundTag(outboundTag) {
		return true
	}

	balancerTag := stringFromAny(m["balancerTag"])
	if balancerTag != "" {
		if IsHiddenBalancerTag(balancerTag) || hiddenBalancerTagMap[balancerTag] {
			return true
		}
	}

	for _, inboundTag := range stringListFromAny(m["inboundTag"]) {
		if hiddenInboundTagMap[inboundTag] {
			return true
		}
	}

	return false
}

func filterVisibleBalancers(balancers []any) []any {
	if len(balancers) == 0 {
		return balancers
	}

	visible := make([]any, 0, len(balancers))

	for _, balancer := range balancers {
		if isHiddenBalancerObject(balancer) {
			continue
		}

		visible = append(visible, balancer)
	}

	return visible
}

func filterVisibleRoutingRules(rules []any, hiddenInboundTagMap map[string]bool, hiddenBalancerTagMap map[string]bool) []any {
	if len(rules) == 0 {
		return rules
	}

	visible := make([]any, 0, len(rules))

	for _, rule := range rules {
		if isHiddenRoutingRule(rule, hiddenInboundTagMap, hiddenBalancerTagMap) {
			continue
		}

		visible = append(visible, rule)
	}

	return visible
}

func mergeHiddenByVisibleOrdinal(current []any, submitted []any, isHidden func(any) bool) []any {
	if len(current) == 0 {
		return submitted
	}

	hiddenBeforeVisibleIndex := make(map[int][]any)
	hiddenTail := make([]any, 0)
	pendingHidden := make([]any, 0)

	visibleIndex := 0

	for _, item := range current {
		if isHidden(item) {
			pendingHidden = append(pendingHidden, item)
			continue
		}

		if len(pendingHidden) > 0 {
			hiddenBeforeVisibleIndex[visibleIndex] = append(hiddenBeforeVisibleIndex[visibleIndex], pendingHidden...)
			pendingHidden = nil
		}

		visibleIndex++
	}

	if len(pendingHidden) > 0 {
		hiddenTail = append(hiddenTail, pendingHidden...)
	}

	merged := make([]any, 0, len(current)+len(submitted))
	submittedVisibleIndex := 0

	for _, item := range submitted {
		if isHidden(item) {
			continue
		}

		if hiddenGroup, ok := hiddenBeforeVisibleIndex[submittedVisibleIndex]; ok {
			merged = append(merged, hiddenGroup...)
			delete(hiddenBeforeVisibleIndex, submittedVisibleIndex)
		}

		merged = append(merged, item)
		submittedVisibleIndex++
	}

	leftoverIndexes := make([]int, 0, len(hiddenBeforeVisibleIndex))
	for index := range hiddenBeforeVisibleIndex {
		leftoverIndexes = append(leftoverIndexes, index)
	}
	sort.Ints(leftoverIndexes)

	for _, index := range leftoverIndexes {
		merged = append(merged, hiddenBeforeVisibleIndex[index]...)
	}

	merged = append(merged, hiddenTail...)

	return merged
}

func routingMapFromConfig(cfg map[string]any) map[string]any {
	routing, ok := cfg["routing"].(map[string]any)
	if !ok || routing == nil {
		routing = make(map[string]any)
		cfg["routing"] = routing
	}

	return routing
}

func FilterVisibleBalancersAndRoutingInXraySetting(xraySetting string) string {
	if strings.TrimSpace(xraySetting) == "" {
		return xraySetting
	}

	var cfg map[string]any
	if err := json.Unmarshal([]byte(xraySetting), &cfg); err != nil {
		return xraySetting
	}

	routingRaw, ok := cfg["routing"]
	if !ok || routingRaw == nil {
		return xraySetting
	}

	routing, ok := routingRaw.(map[string]any)
	if !ok {
		return xraySetting
	}

	balancers, _ := routing["balancers"].([]any)
	hiddenBalancerTagMap := hiddenBalancerTagsFromObjects(balancers)

	if len(balancers) > 0 {
		routing["balancers"] = filterVisibleBalancers(balancers)
	}

	rules, _ := routing["rules"].([]any)
	if len(rules) > 0 {
		routing["rules"] = filterVisibleRoutingRules(rules, hiddenInboundTags(), hiddenBalancerTagMap)
	}

	raw, err := json.Marshal(cfg)
	if err != nil {
		return xraySetting
	}

	return string(raw)
}

func MergeHiddenBalancersAndRoutingIntoXraySetting(submittedSetting string, currentSetting string) (string, error) {
	if strings.TrimSpace(submittedSetting) == "" || strings.TrimSpace(currentSetting) == "" {
		return submittedSetting, nil
	}

	var submitted map[string]any
	if err := json.Unmarshal([]byte(submittedSetting), &submitted); err != nil {
		return submittedSetting, err
	}

	var current map[string]any
	if err := json.Unmarshal([]byte(currentSetting), &current); err != nil {
		return submittedSetting, nil
	}

	currentRoutingRaw, ok := current["routing"]
	if !ok || currentRoutingRaw == nil {
		return submittedSetting, nil
	}

	currentRouting, ok := currentRoutingRaw.(map[string]any)
	if !ok {
		return submittedSetting, nil
	}

	submittedRouting := routingMapFromConfig(submitted)

	currentBalancers, _ := currentRouting["balancers"].([]any)
	submittedBalancers, _ := submittedRouting["balancers"].([]any)

	currentHiddenBalancerTagMap := hiddenBalancerTagsFromObjects(currentBalancers)

	if len(currentBalancers) > 0 {
		submittedRouting["balancers"] = mergeHiddenByVisibleOrdinal(
			currentBalancers,
			submittedBalancers,
			isHiddenBalancerObject,
		)
	}

	currentRules, _ := currentRouting["rules"].([]any)
	submittedRules, _ := submittedRouting["rules"].([]any)

	hiddenInboundTagMap := hiddenInboundTags()

	if len(currentRules) > 0 {
		submittedRouting["rules"] = mergeHiddenByVisibleOrdinal(
			currentRules,
			submittedRules,
			func(rule any) bool {
				return isHiddenRoutingRule(rule, hiddenInboundTagMap, currentHiddenBalancerTagMap)
			},
		)
	}

	raw, err := json.Marshal(submitted)
	if err != nil {
		return submittedSetting, err
	}

	return string(raw), nil
}
