package oidc

func scopeIsSubset(required, granted []string) bool {
	if len(required) == 0 {
		return true
	}
	set := make(map[string]struct{}, len(granted))
	for _, value := range granted {
		set[value] = struct{}{}
	}
	for _, value := range required {
		if _, ok := set[value]; !ok {
			return false
		}
	}
	return true
}

func mergeScopes(base, extra []string) []string {
	out := append([]string{}, base...)
	out = append(out, extra...)
	return normalizeScopes(out)
}
