package hunt

type IOCSeed struct {
	Term        string
	Description string
	Points      int
}

type Hunt struct {
	Key        string
	Title      string
	Hypothesis string
	Background string
	LabScope   []string
	Seeds      []IOCSeed
	MaxScore   int
}

var Hunts = []Hunt{
	{
		Key:        "hunt-ransomware",
		Title:      "Ransomware IOC Hunt",
		Hypothesis: "There is evidence of ransomware activity in endpoint logs. Hunt for file encryption indicators, shadow copy deletion, and lateral movement over SMB.",
		Background: "Your SIEM fired a correlation rule for 'high write IOPS on the file server'. You've been tasked to hunt for ransomware IOCs and determine blast radius before escalating to IR.",
		LabScope:   []string{"ransomware-01"},
		Seeds: []IOCSeed{
			{"vssadmin", "Shadow copy deletion command executed", 20},
			{"LOCKED", "File extension applied by ransomware", 20},
			{"shadow", "Reference to volume shadow copies", 15},
			{"encrypt", "Encryption-related process or file activity", 15},
			{"445", "SMB port — lateral spread channel", 15},
			{"ransom", "Ransom note creation or process name", 15},
		},
		MaxScore: 100,
	},
	{
		Key:        "hunt-lolbins",
		Title:      "LOLBin Abuse Hunt",
		Hypothesis: "An attacker is using legitimate Windows binaries (LOLBins) to evade AV detection. Hunt for certutil, mshta, or encoded PowerShell usage that deviates from baseline.",
		Background: "Threat intel reported a campaign in your sector using living-off-the-land techniques to bypass security controls. Hunt proactively for suspicious built-in tool usage.",
		LabScope:   []string{"living-off-land-01"},
		Seeds: []IOCSeed{
			{"certutil", "certutil.exe used as download tool", 25},
			{"mshta", "mshta.exe executing remote script", 25},
			{"EncodedCommand", "PowerShell obfuscation flag (-enc)", 25},
			{"urlcache", "certutil -urlcache download indicator", 25},
		},
		MaxScore: 100,
	},
	{
		Key:        "hunt-insider",
		Title:      "Insider Data Exfiltration Hunt",
		Hypothesis: "A privileged user may be staging data for exfiltration. Hunt for unusual file access patterns, USB activity, and anomalous cloud upload behaviour.",
		Background: "HR has flagged an employee who submitted resignation last week and has access to sensitive R&D files. You've been asked to investigate before their last day.",
		LabScope:   []string{"insider-threat-01"},
		Seeds: []IOCSeed{
			{"usb", "USB device connected and used", 20},
			{"resignation", "HR flag linked to departing employee", 20},
			{"bulk", "Bulk file access or copy anomaly", 20},
			{"personal", "Personal cloud storage destination", 20},
			{"confidential", "Access to classified or restricted files", 20},
		},
		MaxScore: 100,
	},
	{
		Key:        "hunt-supply-chain",
		Title:      "Supply Chain Compromise Hunt",
		Hypothesis: "A recently installed software package may contain malicious code. Hunt for postinstall script execution, unexpected child processes from package managers, and C2 connections from developer machines.",
		Background: "A dependency confusion attack was reported against companies in your industry. Hunt for evidence that any npm/pip postinstall scripts executed malicious payloads in your dev environment.",
		LabScope:   []string{"supply-chain-01"},
		Seeds: []IOCSeed{
			{"postinstall", "npm postinstall script triggered", 25},
			{"powershell", "PowerShell spawned from package manager", 25},
			{"download", "Unexpected download during install", 25},
			{"scheduled", "Persistence scheduled task created", 25},
		},
		MaxScore: 100,
	},
}

func Get(key string) *Hunt {
	for i, h := range Hunts {
		if h.Key == key {
			return &Hunts[i]
		}
	}
	return nil
}
