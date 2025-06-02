package policy

// type BlockAddrsInput struct {
// 	BaseCLIInput
// 	AutoBackup     bool
// 	ResourceID     string
// 	RuleNamePrefix RuleNamePrefix
// 	PriorityStart  int
// 	Output         bool
// 	DryRun         bool
// 	Filepath       string
// 	Addrs          IPNets
// 	MaxRules       int
// }

// func Block(in BlockAddrsInput) error {
// 	s := session.New()
//
// 	// policyID, err := GetWAFPolicyResourceID(s, GetWAFPolicyResourceIDInput{
// 	// 	SubscriptionID: in.SubscriptionID,
// 	// 	RawPolicyID:    in.ResourceID,
// 	// 	ConfigPath:     in.ConfigPath,
// 	// })
// 	// if err != nil {
// 	// 	return err
// 	// }
//
// 	policyResourceId := config.ParseResourceID(in.ResourceID)
//
// 	policy, err := GetRawPolicy(s, policyResourceId.SubscriptionID, policyResourceId.ResourceGroup, policyResourceId.Name)
// 	if err != nil {
// 		return err
// 	}
//
// 	if in.Filepath != "" {
// 		in.Addrs, err = readIPsFromFile(in.Filepath)
// 		if err != nil {
// 			return err
// 		}
// 	}
//
// 	modified, _, err := UpdatePolicyCustomRulesIPMatchPrefixes(UpdatePolicyCustomRulesIPMatchPrefixesInput{
// 		Policy:         policy,
// 		SubscriptionID: in.SubscriptionID,
// 		ResourceID:     policyResourceId,
// 		Action:         actionBlock,
// 		RuleNamePrefix: in.RuleNamePrefix,
// 		PriorityStart:  in.PriorityStart,
// 		Output:         in.Output,
// 		Addrs:          in.Addrs,
// 		MaxRules:       in.MaxRules,
// 	})
// 	if err != nil {
// 		return err
// 	}
//
// 	if in.Output {
// 		fmt.Println()
//
// 		if modified {
// 			fmt.Println("addresses blocked")
// 		} else {
// 			fmt.Println("no change necessary")
// 		}
// 	}
//
// 	return nil
// }
