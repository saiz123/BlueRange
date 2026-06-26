package campaign

type Stage struct {
	Num              int
	Title            string
	AlertTemplateKey string
	TransitionHint   string
}

type Campaign struct {
	Key          string
	Title        string
	Description  string
	Difficulty   string
	MITRESummary string
	Stages       []Stage
}

var Campaigns = []Campaign{
	{
		Key:          "apt-fin7",
		Title:        "Operation FIN7",
		Description:  "Track a sophisticated financial threat actor through a multi-stage attack targeting your finance department. Each stage reveals the next layer of the intrusion.",
		Difficulty:   "realistic",
		MITRESummary: "T1566 → T1059 → T1071 → T1021 → T1041",
		Stages: []Stage{
			{1, "Initial Phishing Wave", "phishing-mass-click",
				"Multiple users clicked the link. Expect follow-on execution on affected endpoints."},
			{2, "Malware Execution", "malware-exec-endpoint",
				"The payload is running. Look for C2 beaconing and persistence mechanisms."},
			{3, "C2 Beacon Established", "c2-beacon-pattern",
				"Command channel is active. Attacker is likely preparing for lateral movement."},
			{4, "Lateral Movement", "lateral-move-creds",
				"Harvested credentials being used across the network. How far have they spread?"},
			{5, "Active Data Exfiltration", "active-exfil-c2",
				"Data is leaving the network. Confirm the volume and contain the source host immediately."},
		},
	},
	{
		Key:          "ransomware-lockbit",
		Title:        "LockBit Ransomware Campaign",
		Description:  "A ransomware group has targeted your organization. Investigate each stage of the attack — from initial access to encryption — before the damage becomes irreversible.",
		Difficulty:   "core",
		MITRESummary: "T1110 → T1068 → T1021 → T1486",
		Stages: []Stage{
			{1, "RDP Brute Force Success", "rdp-brute-success",
				"Attacker has a foothold via RDP. Privilege escalation is the next likely move."},
			{2, "Privilege Escalation", "priv-esc-local-admin",
				"They have local admin. Expect credential dumping and preparation for lateral movement."},
			{3, "Lateral Spread", "lateral-move-creds",
				"Credentials are being used across multiple hosts. Ransomware deployment is imminent."},
			{4, "Ransomware Detonation", "ransom-multi-host",
				"Ransomware has deployed. Isolate affected hosts and initiate IR procedures immediately."},
		},
	},
	{
		Key:          "insider-theft",
		Title:        "Trusted Insider Data Theft",
		Description:  "A disgruntled employee with privileged access is systematically stealing company IP before their departure. Follow the evidence trail from anomalous access to confirmed exfiltration.",
		Difficulty:   "core",
		MITRESummary: "T1078 → T1048 → T1567",
		Stages: []Stage{
			{1, "Anomalous After-Hours Access", "anomalous-after-hours",
				"Late-night access to sensitive systems. Determine what was accessed and assess intent."},
			{2, "Bulk File Collection", "insider-bulk-copy",
				"Large volumes of sensitive data being copied. Determine destination and preserve evidence."},
			{3, "Cloud Exfiltration", "large-upload-cloud",
				"Data is moving to personal cloud storage. Confirm breach and prepare for legal hold."},
		},
	},
	{
		Key:          "cloud-breach",
		Title:        "Cloud Account Takeover",
		Description:  "An attacker has gained access to your AWS environment via exposed credentials. Track the attack from initial credential exposure through to data breach.",
		Difficulty:   "realistic",
		MITRESummary: "T1552 → T1078 → T1530 → T1041",
		Stages: []Stage{
			{1, "Credentials Exposed in Git", "cred-in-git",
				"AWS keys committed publicly. Assume the attacker already has them — move fast."},
			{2, "AWS Root Account Compromise", "aws-root-login",
				"Root account accessed from foreign IP. IAM is being modified — what's their objective?"},
			{3, "S3 Bucket Made Public", "cloud-bucket-public",
				"Sensitive bucket exposed. Assess what data is now publicly accessible."},
			{4, "Active Cloud Exfiltration", "active-exfil-c2",
				"Data actively being exfiltrated. Quantify the loss and revoke all compromised credentials."},
		},
	},
}

func Get(key string) *Campaign {
	for i, c := range Campaigns {
		if c.Key == key {
			return &Campaigns[i]
		}
	}
	return nil
}
