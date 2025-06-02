package policy

const (
	actionBlock = "Block"
	actionAllow = "Allow"
)

var ValidRuleExclusionMatchVariables = [...]string{
	"RequestCookieNames",
	"RequestHeaderNames",
	"QueryStringArgNames",
	"RequestBodyPostArgNames",
	"RequestBodyJsonArgNames",
}

var ValidRuleExclusionMatchOperators = [...]string{
	"Contains",
	"EndsWith",
	"Equals",
	"EqualsAny",
	"StartsWith",
}
