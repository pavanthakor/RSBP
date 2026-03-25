package detection

import "sort"

var ruleToMITRE = map[string][]string{
	"HighRiskIPRule":         {"T1071"},
	"SuspiciousCommandRule":  {"T1059"},
	"CorrelatedBehaviorRule": {"T1104"},
	"LowFPCombinedRule":      {"T1571"},
	"KnownC2PortRule":        {"T1095"},
	"EphemeralPortRule":      {"T1048"},
	"ThreatIntelRule":        {"T1071"},
	"UnusualTimeRule":        {"T1029"},
}

func MITREForRules(ruleIDs []string) []string {
	if len(ruleIDs) == 0 {
		return []string{"T1059", "T1104"}
	}
	set := make(map[string]struct{}, len(ruleIDs))
	for _, id := range ruleIDs {
		techniques := ruleToMITRE[id]
		for _, t := range techniques {
			if t == "" {
				continue
			}
			set[t] = struct{}{}
		}
	}
	if len(set) == 0 {
		return []string{"T1059", "T1104"}
	}
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
